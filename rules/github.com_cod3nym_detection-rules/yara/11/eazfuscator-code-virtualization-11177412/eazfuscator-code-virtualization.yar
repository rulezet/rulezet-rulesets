rule Eazfuscator_Code_Virtualization : suspicious
{
	meta:
		name = "Eazfuscator"
		category = "obfuscation"
		description = "Eazfuscator.NET code virtualization"
		author = "Jonathan Peters"
		created = "2024-01-01"
		reliability = 90
		tlp = "TLP:white"
		sample = "53d5c2574c7f70b7aa69243916acf6e43fe4258fbd015660032784e150b3b4fa"
	strings:
		$sa1 = "BinaryReader" ascii
		$sa2 = "GetManifestResourceStream" ascii
		$sa3 = "get_HasElementType" ascii

		$op1 = { 28 [2] 00 06 28 [2] 00 06 72 [2] 00 70 ?? 1? 2D 0? 26 26 26 26 2B }
		$op2 = { 7E [3] 04 2D 3D D0 [3] 02 28 [3] 0A 6F [3] 0A 72 [3] 70 6F [3] 0A 20 80 00 00 00 8D ?? 00 00 01 25 D0 [3] 04 28 [3] 0A 28 [3] 06 28 [3] 06 80 [3] 04 7E [3] 04 2A } 		$op3 = { 02 20 [4] 1F 09 73 [4] 7D [3] 04 }
	condition:
		uint16(0) == 0x5a4d and
		all of ($sa*) and
		2 of ($op*)
}
rule ConfuserEx_Naming_Pattern : suspicious
{
	meta:
		name = "ConfuserEx"
		category = "obfuscation"
		description = "ConfuserEx Renaming Pattern"
		author = "Jonathan Peters"
		created = "2024-01-03"
		reliability = 90
	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii 
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }

		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}
	condition:
		uint16(0) == 0x5a4d
		and 2 of ($s*)
		and #name_pattern > 5
}
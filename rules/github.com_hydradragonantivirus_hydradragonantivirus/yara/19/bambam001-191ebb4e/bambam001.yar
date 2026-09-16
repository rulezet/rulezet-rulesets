rule bambam001
{
	meta:
		author = "PEiD"
		description = "bambam 0.01 -> bedrock"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B }
	condition:
		$a0
}
rule progprot
{
	meta:
		author = "PEiD"
		description = "Program Protector XP 1.0 -> BluMental"
		group = "162"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }
	condition:
		$a0
}
import "pe"
rule telock_041x
{
	meta:
		author = "PEiD"
		description = "tElock 0.41x -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }
	condition:
		$a0 at pe.entry_point
}
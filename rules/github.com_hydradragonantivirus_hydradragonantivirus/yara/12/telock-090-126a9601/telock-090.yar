import "pe"
rule telock_090
{
	meta:
		author = "PEiD"
		description = "tElock 0.90 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { ?? ?? E8 02 ?? ?? ?? E8 ?? E8 ?? ?? ?? ?? 5E 2B C9 58 74 02 CD 20 B9 FF 10 }
	condition:
		$a0 at pe.entry_point
}
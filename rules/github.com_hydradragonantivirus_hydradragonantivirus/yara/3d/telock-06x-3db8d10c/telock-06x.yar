import "pe"
rule telock_06x
{
	meta:
		author = "PEiD"
		description = "tElock 0.6x -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0 08 F3 EB FF }
	condition:
		$a0 at pe.entry_point
}
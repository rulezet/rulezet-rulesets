import "pe"
rule telock_092b1
{
	meta:
		author = "PEiD"
		description = "tElock 0.92b1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 87 E9 FF FF ?? ?? ?? B8 }
	condition:
		$a0 at pe.entry_point
}
rule telock_080
{
	meta:
		author = "PEiD"
		description = "tElock 0.80 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 F9 11 ?? ?? C3 83 }
	condition:
		$a0
}
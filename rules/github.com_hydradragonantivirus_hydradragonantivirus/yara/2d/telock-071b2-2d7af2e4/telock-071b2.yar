rule telock_071b2
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b2 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 44 11 ?? ?? C3 83 }
	condition:
		$a0
}
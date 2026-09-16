rule telock_0981
{
	meta:
		author = "PEiD"
		description = "tElock 0.98b1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 25 E4 FF FF }
	condition:
		$a0
}
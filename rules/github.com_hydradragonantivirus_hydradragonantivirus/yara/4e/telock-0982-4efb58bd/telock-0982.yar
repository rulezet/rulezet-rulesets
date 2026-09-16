rule telock_0982
{
	meta:
		author = "PEiD"
		description = "tElock 0.98b2 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 1B E4 FF FF }
	condition:
		$a0
}
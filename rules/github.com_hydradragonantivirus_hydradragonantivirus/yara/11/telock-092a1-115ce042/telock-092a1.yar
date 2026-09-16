rule telock_092a1
{
	meta:
		author = "PEiD"
		description = "tElock 0.92a1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 6E E7 FF FF }
	condition:
		$a0
}
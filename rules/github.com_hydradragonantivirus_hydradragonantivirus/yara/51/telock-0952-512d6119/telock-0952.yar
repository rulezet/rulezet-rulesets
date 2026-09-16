rule telock_0952
{
	meta:
		author = "PEiD"
		description = "tElock 0.95 build 2 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 DD E4 FF FF }
	condition:
		$a0
}
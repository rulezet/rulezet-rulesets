rule telock_085f
{
	meta:
		author = "PEiD"
		description = "tElock 0.85f -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 02 ?? ?? ?? CD 20 E8 ?? ?? ?? ?? 5E 2B C9 58 74 02 CD 20 B9 }
	condition:
		$a0
}
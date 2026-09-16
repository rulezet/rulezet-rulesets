rule _Petite_21_
{
	meta:
		description = "Petite 2.1"
	strings:
		$0 = {64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8}
	condition:
		$0
}
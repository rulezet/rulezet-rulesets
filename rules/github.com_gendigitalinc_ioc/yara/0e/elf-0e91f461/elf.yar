rule ELF
{
	strings:
		$h01 = { 7F 45 4C 46 (01|02) (01|02) 01 }
	condition:
		$h01 at 0
}
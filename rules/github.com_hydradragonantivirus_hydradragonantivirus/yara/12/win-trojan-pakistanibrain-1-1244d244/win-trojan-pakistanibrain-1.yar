rule Win_Trojan_PakistaniBrain_1
{
strings:
	$a0 = { a0067ca2097c8b0e077c890e0a7ce857 }


condition:
	$a0
}
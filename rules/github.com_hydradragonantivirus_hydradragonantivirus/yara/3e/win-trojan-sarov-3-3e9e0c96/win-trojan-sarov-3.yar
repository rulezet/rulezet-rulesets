rule Win_Trojan_Sarov_3
{
strings:
	$a0 = { 0100465e81ee980456ba9504803454464a75f9 }


condition:
	$a0
}
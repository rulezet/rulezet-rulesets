rule Win_Trojan_dBase_2
{
strings:
	$a0 = { b90001ba00008eda33db50cd2658403c }


condition:
	$a0
}
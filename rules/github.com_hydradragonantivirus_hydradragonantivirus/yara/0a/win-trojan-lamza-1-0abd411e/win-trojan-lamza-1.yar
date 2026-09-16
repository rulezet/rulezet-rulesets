rule Win_Trojan_Lamza_1
{
strings:
	$a0 = { 55e8000000005d81ed5b13400083fd017479ffa56d134000 }


condition:
	$a0
}
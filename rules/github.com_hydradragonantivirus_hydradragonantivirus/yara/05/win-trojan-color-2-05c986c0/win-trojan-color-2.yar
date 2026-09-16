rule Win_Trojan_Color_2
{
strings:
	$a0 = { b70188a56d0147e2f5b890e98984 }


condition:
	$a0
}
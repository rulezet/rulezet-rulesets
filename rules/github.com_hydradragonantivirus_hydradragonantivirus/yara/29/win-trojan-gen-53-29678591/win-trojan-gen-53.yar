rule Win_Trojan_Gen_53
{
strings:
	$a0 = { 0f8db74d01bc82063134312446 }


condition:
	$a0
}
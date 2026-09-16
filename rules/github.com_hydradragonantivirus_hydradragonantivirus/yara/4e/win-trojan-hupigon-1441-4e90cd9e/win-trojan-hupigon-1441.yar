rule Win_Trojan_Hupigon_1441
{
strings:
	$a0 = { 683f89a9dfe92cda04006b8792876025 }


condition:
	$a0
}
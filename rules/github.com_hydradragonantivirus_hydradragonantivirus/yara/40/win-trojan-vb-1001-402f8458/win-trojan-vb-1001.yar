rule Win_Trojan_VB_1001
{
strings:
	$a0 = { 89e18b49f2b9fa6123a14189c84881c00503014f89c353b8cfab4a514081c0 }


condition:
	$a0
}
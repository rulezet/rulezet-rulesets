rule Win_Trojan_Small_5377
{
strings:
	$a0 = { 505b505e81e800444000f7d0 }


condition:
	$a0
}
rule Win_Trojan_Small_4361
{
strings:
	$a0 = { 89c3505e81e800444000f7d0 }


condition:
	$a0
}
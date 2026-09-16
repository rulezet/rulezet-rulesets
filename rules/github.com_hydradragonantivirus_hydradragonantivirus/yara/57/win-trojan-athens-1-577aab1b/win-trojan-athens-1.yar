rule Win_Trojan_Athens_1
{
strings:
	$a0 = { 505351e80100735d83ed0890fc0e1fbe280003f58bfe }


condition:
	$a0
}
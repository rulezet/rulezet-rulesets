rule Win_Trojan_Exvc_1
{
strings:
	$a0 = { bd00018db612008bfeb9d302ac34??aae2fa }


condition:
	$a0
}
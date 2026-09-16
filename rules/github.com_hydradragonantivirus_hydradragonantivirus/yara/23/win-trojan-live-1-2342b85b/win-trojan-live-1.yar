rule Win_Trojan_Live_1
{
strings:
	$a0 = { e90000fa95e800005e83c619fc8bfe33d2b9810151ad33d0e2fb5931154747e2fa }


condition:
	$a0
}
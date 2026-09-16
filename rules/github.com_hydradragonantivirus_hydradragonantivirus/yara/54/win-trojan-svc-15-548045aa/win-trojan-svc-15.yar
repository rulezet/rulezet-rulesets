rule Win_Trojan_SVC_15
{
strings:
	$a0 = { a41f122e8ab4201281c68b11e8a808 }


condition:
	$a0
}
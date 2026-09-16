rule Win_Trojan_Lemming_5
{
strings:
	$a0 = { 07be1801e800005d81ed09012e803200e3044946ebf6 }


condition:
	$a0
}
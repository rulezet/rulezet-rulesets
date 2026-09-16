rule Win_Trojan_Bowl_4
{
strings:
	$a0 = { cc5d81ed0601c686120101b800003d01007503e9a902e89502e87b02 }


condition:
	$a0
}
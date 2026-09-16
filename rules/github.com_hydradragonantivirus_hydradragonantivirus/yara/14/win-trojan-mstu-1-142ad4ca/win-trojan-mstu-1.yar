rule Win_Trojan_MSTU_1
{
strings:
	$a0 = { 1a33d2cd211fb44e8d946301cd217208e8caff741b }


condition:
	$a0
}
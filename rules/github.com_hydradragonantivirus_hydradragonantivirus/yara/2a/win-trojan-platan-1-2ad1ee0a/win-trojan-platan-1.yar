rule Win_Trojan_Platan_1
{
strings:
	$a0 = { d776e4176dc817f1900dae40bb7320bddcc57b9dccbbbfffffebf7e7cfbf8f3cfbf7cf3ef9f7cf7279c9fcfe7efe58c38232c10ac4117b6ec61982e8825a5e7a }


condition:
	$a0
}
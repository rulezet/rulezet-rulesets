rule Win_Trojan_Xhuna_1
{
strings:
	$a0 = { 7061727420423a[0-20]7061727420413a }

	$a1 = { 2f5f78756e5f6861 }


condition:
	$a0 and $a1
}
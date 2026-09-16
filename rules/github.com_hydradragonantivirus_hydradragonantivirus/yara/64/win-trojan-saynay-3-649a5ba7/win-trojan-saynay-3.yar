rule Win_Trojan_SayNay_3
{
strings:
	$a0 = { 3e8b6e0081ed0d01fb8db69802bf0001b90900f3 }


condition:
	$a0
}
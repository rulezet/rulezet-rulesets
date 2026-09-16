rule Win_Trojan_Tony_4
{
strings:
	$a0 = { b901008af5b402e89100725bf6c28074 }


condition:
	$a0
}
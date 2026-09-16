rule Win_Trojan_Dropper_2
{
strings:
	$a0 = { b43fcd21e83b0033d2b97603b440cd21 }


condition:
	$a0
}
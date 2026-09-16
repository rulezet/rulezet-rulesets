rule Win_Trojan_AIDS_2
{
strings:
	$a0 = { efe3bfca031e57bfca031ee8b4e3 }


condition:
	$a0
}
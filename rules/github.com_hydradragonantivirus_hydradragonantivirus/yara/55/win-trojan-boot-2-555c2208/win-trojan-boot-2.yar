rule Win_Trojan_Boot_2
{
strings:
	$a0 = { d8a16d04258f177510e8b80050e89f0081f1c0ffd1 }


condition:
	$a0
}
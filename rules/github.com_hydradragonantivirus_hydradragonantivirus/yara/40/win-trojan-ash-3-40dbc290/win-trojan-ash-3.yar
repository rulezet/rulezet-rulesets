rule Win_Trojan_Ash_3
{
strings:
	$a0 = { 028db63a0252eb29b41aba8000cd2133c0 }


condition:
	$a0
}
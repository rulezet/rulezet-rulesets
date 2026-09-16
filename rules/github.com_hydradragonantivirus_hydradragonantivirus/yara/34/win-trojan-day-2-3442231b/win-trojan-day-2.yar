rule Win_Trojan_Day_2
{
strings:
	$a0 = { b43fcd218bf25a7278807c0644754180 }


condition:
	$a0
}
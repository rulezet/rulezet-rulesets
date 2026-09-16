rule Win_Trojan_Ionkin_1
{
strings:
	$a0 = { 02b90600cd217303eb61908d5e028b1f81fb4d5a75 }


condition:
	$a0
}
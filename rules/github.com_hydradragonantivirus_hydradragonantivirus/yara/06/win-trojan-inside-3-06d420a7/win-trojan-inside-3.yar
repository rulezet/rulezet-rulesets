rule Win_Trojan_Inside_3
{
strings:
	$a0 = { 010100550000000000ffffef05000097000000020000000903 }


condition:
	$a0
}
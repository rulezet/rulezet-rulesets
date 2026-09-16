rule Win_Trojan_Darkmoon_10
{
strings:
	$a0 = { 6f672e646174838a52f2bf254461726b4d6f6f6e252e4129695323fbbb2caa20 }


condition:
	$a0
}
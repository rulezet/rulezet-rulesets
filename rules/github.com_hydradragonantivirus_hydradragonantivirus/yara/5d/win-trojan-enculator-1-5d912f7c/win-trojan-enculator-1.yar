rule Win_Trojan_Enculator_1
{
strings:
	$a0 = { 40b92407ba000103d53e8b9e14013e899e12013e8b9e36 }


condition:
	$a0
}
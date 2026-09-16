rule Win_Trojan_Sunnyvale_1
{
strings:
	$a0 = { 891ead098d160001b82125cd210706bb2c00268b078e }


condition:
	$a0
}
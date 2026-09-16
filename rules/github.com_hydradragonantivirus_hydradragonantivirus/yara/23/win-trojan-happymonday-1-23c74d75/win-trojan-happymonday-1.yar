rule Win_Trojan_HappyMonday_1
{
strings:
	$a0 = { e122204c414e4353504f4cee53553ffc434b4552532e }


condition:
	$a0
}
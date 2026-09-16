rule Win_Trojan_Lunch_3
{
strings:
	$a0 = { 899dbb002bc981c2c500b44eeb02b44f }


condition:
	$a0
}
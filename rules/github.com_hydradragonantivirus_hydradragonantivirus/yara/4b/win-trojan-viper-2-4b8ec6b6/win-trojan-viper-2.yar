rule Win_Trojan_Viper_2
{
strings:
	$a0 = { 03ba0001b44090cd21e80100c3bb }


condition:
	$a0
}
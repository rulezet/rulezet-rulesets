rule Win_Trojan_Ascii_208_2_139_48_1
{
strings:
	$a0 = { 3230382e322e3133392e3438 }


condition:
	$a0
}
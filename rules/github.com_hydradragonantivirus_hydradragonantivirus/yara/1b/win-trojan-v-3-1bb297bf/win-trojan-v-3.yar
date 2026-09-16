rule Win_Trojan_V_3
{
strings:
	$a0 = { 35cd2183fbf07503e98b00b0002ea21b00b4002ea317 }


condition:
	$a0
}
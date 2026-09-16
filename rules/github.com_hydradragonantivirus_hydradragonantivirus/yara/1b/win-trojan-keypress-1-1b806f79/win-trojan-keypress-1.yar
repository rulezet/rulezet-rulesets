rule Win_Trojan_Keypress_1
{
strings:
	$a0 = { dbc7070100b42acd2180fe04752b33d2b419cd2133db8e }


condition:
	$a0
}
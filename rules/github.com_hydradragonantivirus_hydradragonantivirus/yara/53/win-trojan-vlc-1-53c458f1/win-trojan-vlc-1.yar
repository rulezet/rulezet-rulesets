rule Win_Trojan_VLC_1
{
strings:
	$a0 = { 030190b9330281355d014747e2f8c3 }


condition:
	$a0
}
rule Win_Trojan_Ascii_192_210_53_18_1
{
strings:
	$a0 = { 3139322e3231302e35332e3138 }


condition:
	$a0
}
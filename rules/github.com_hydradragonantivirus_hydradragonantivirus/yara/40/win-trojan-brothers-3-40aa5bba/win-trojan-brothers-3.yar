rule Win_Trojan_Brothers_3
{
strings:
	$a0 = { 4bcd217203e9d7005e56 }


condition:
	$a0
}
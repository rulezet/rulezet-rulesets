rule Win_Trojan_Horse_13
{
strings:
	$a0 = { f8b84b4bcd2172151e0e1f8bf783ee03 }


condition:
	$a0
}
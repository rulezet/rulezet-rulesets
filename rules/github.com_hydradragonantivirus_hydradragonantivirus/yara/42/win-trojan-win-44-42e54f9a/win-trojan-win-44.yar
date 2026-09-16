rule Win_Trojan_Win_44
{
strings:
	$a0 = { c2ec0683d100e8ed0159ba7200e8ca01585a593d00107e0c2d001081ea001083d900ebbb8b3614 }


condition:
	$a0
}
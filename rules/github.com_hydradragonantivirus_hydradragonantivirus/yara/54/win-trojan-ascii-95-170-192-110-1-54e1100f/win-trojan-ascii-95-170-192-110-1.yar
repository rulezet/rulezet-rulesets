rule Win_Trojan_Ascii_95_170_192_110_1
{
strings:
	$a0 = { 39352e3137302e3139322e313130 }


condition:
	$a0
}
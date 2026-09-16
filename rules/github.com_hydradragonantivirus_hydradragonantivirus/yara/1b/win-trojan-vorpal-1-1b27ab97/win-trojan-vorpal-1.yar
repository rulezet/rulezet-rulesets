rule Win_Trojan_Vorpal_1
{
strings:
	$a0 = { 0700509a36018d00e93dffbff0040e579af80ab9008b86c8fe3b8642fa7403e908ffbf94001e57 }


condition:
	$a0
}
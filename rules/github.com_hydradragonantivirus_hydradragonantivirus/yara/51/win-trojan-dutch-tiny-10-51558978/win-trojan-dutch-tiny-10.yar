rule Win_Trojan_Dutch_Tiny_10
{
strings:
	$a0 = { 408d940501b9e803cd219ce8c8ff9d }


condition:
	$a0
}
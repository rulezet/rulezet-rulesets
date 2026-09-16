rule Win_Trojan_Headache_1
{
strings:
	$a0 = { 01018a27bb02018a0786c48bf0b41a8d94b802cd2133c9 }


condition:
	$a0
}
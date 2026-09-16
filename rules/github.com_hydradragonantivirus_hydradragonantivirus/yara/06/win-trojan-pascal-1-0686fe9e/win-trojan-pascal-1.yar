rule Win_Trojan_Pascal_1
{
strings:
	$a0 = { 21e800005e81ee5c01888448018b8406 }


condition:
	$a0
}
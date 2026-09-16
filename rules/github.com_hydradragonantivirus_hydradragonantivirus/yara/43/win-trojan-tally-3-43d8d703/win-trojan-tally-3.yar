rule Win_Trojan_Tally_3
{
strings:
	$a0 = { 1fe800005d81ed0601be030203f5fe44f9b41a8bd683c21ccd21b44e33c983ea22cd210f82c1008bd683c23ab842 }


condition:
	$a0
}
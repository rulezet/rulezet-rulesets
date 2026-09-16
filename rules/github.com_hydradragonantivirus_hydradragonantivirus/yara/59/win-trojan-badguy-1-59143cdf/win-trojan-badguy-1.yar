rule Win_Trojan_Badguy_1
{
strings:
	$a0 = { 0190b90b1190b44ecd2190730390 }


condition:
	$a0
}
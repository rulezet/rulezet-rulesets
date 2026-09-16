rule Win_Trojan_Anto_1
{
strings:
	$a0 = { 87cfcd21b4405a87cfcd21b43ecd21b44fcd2173 }


condition:
	$a0
}
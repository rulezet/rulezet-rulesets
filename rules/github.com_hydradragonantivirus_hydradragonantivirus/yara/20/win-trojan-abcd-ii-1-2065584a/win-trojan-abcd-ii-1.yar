rule Win_Trojan_ABCD_II_1
{
strings:
	$a0 = { 509d8b4dfc8b45fe8a2532c4aa8ac4e2f7c333c0509d8b4dfc8b45fe02c48945fe8a2532c4aa }


condition:
	$a0
}
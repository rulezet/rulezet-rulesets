rule Win_Trojan_Small_4586
{
strings:
	$a0 = { e938000000e969020000e970020000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc558bec }


condition:
	$a0
}
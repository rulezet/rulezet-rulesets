rule Win_Trojan_Small_4081
{
strings:
	$a0 = { e803000000cceb705941ffe1 }


condition:
	$a0
}
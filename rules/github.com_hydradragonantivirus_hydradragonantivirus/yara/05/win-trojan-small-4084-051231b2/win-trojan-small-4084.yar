rule Win_Trojan_Small_4084
{
strings:
	$a0 = { e803000000e8eb4c83042401c3 }


condition:
	$a0
}
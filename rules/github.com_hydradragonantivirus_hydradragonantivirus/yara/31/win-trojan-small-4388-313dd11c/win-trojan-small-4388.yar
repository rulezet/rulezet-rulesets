rule Win_Trojan_Small_4388
{
strings:
	$a0 = { 89c689c789c381c000e4bdfff7d85050 }


condition:
	$a0
}
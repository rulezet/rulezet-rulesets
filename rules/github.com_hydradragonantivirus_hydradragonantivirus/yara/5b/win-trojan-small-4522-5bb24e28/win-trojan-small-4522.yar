rule Win_Trojan_Small_4522
{
strings:
	$a0 = { bd????420055b9??????008b11ffd201d5e84400000089e951e82c00000055e8 }


condition:
	$a0
}
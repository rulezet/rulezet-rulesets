rule Win_Trojan_Uruguay_8
{
strings:
	$a0 = { e800005e83c60e159301b99c0429044646 }


condition:
	$a0
}
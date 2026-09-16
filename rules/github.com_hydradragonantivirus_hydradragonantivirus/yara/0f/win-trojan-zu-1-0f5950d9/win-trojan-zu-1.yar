rule Win_Trojan_ZU_1
{
strings:
	$a0 = { e20190ba0000b440cd21b80157bfc801 }


condition:
	$a0
}
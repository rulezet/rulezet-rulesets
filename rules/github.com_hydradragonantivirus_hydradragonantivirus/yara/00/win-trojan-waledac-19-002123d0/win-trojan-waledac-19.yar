rule Win_Trojan_Waledac_19
{
strings:
	$a0 = { 558bec83ec6c8b053f2b44008d1d7bfc45 }


condition:
	$a0
}
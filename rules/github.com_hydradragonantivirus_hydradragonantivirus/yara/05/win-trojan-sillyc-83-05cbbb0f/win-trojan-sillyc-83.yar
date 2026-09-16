rule Win_Trojan_SillyC_83
{
strings:
	$a0 = { 018a45fca20201b41a81c7b2008bd7cd21b44e33c981 }


condition:
	$a0
}
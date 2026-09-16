rule Win_Trojan_Quell_1
{
strings:
	$a0 = { 0e01b90400b440cd21b8024233d28bcacd21ba1601b90a00b440cd2133c98bd1b80242cd21 }


condition:
	$a0
}
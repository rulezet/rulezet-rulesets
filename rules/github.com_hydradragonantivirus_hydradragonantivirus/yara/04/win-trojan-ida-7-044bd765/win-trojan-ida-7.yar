rule Win_Trojan_Ida_7
{
strings:
	$a0 = { 0300a31402b44033d2b9d80290e8de00b80042e8d100b440ba1302b90300e8cd00b801572e8b16 }


condition:
	$a0
}
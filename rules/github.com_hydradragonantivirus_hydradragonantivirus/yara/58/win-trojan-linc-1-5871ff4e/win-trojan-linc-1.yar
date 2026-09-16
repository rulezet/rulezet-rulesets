rule Win_Trojan_Linc_1
{
strings:
	$a0 = { 02b440ba2002b9c400cd21b800429931c9cd21b440b9 }


condition:
	$a0
}
rule Win_Trojan_VB_1012
{
strings:
	$a0 = { 46616b6520436c69656e74 }

	$a1 = { 6d0061006e00670061005f006d0061006e }


condition:
	$a0 and $a1
}
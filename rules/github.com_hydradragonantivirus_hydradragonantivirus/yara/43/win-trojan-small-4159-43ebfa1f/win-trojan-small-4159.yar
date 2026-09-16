rule Win_Trojan_Small_4159
{
strings:
	$a0 = { cd2a??c0e8??000000??44 }


condition:
	$a0
}
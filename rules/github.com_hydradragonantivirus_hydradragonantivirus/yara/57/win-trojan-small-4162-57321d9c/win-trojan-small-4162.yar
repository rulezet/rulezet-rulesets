rule Win_Trojan_Small_4162
{
strings:
	$a0 = { cd2ae800000000e80b }


condition:
	$a0
}
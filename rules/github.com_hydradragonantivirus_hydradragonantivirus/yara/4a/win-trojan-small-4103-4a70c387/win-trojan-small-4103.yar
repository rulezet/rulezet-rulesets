rule Win_Trojan_Small_4103
{
strings:
	$a0 = { e802000000cd2dcd }


condition:
	$a0
}
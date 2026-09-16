rule Win_Trojan_Nanjing_2
{
strings:
	$a0 = { b600b406cd1ab4ffcd2180fc00751f2ea10700051000 }


condition:
	$a0
}
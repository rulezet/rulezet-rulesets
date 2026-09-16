rule Win_Trojan_Mini3_3
{
strings:
	$a0 = { b8005750cd215152b44033d2b9bb01cd21b000e89a00b440baba01b90400cd215a5958fec0cd21b4 }


condition:
	$a0
}
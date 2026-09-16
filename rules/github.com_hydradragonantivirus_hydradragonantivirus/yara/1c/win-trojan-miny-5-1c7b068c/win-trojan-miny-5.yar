rule Win_Trojan_Miny_5
{
strings:
	$a0 = { 01c606be0134b8005750cd215152b44033d2b9bc01cd21b000e89a00b440babb01b90400cd21 }


condition:
	$a0
}
rule Win_Trojan_Small_4297
{
strings:
	$a0 = { 56575355e859000000e83f000000e892 }


condition:
	$a0
}
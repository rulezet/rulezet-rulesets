rule Win_Trojan_Ultimo_1
{
strings:
	$a0 = { 01030055df0100020003004f0b000065030000030000004f0b }


condition:
	$a0
}
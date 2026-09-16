rule Win_Trojan_Define_1
{
strings:
	$a0 = { b44eba1a01cd21b8013dba9e00cd21 }


condition:
	$a0
}
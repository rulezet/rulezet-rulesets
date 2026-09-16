rule Win_Trojan_Zapper_1
{
strings:
	$a0 = { 01cd0aa06005bb1c01b944048a2732e08827434983f90075f3 }


condition:
	$a0
}
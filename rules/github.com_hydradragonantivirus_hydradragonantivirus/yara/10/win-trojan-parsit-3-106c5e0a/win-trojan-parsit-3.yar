rule Win_Trojan_Parsit_3
{
strings:
	$a0 = { 038bd681ea8702cd21721f3d8703 }


condition:
	$a0
}
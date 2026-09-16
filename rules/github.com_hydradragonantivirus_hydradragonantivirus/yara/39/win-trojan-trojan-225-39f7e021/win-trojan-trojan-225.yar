rule Win_Trojan_Trojan_225
{
strings:
	$a0 = { c6865c0201b41a8d963102cd21b82435cd21899e2d028c86 }


condition:
	$a0
}
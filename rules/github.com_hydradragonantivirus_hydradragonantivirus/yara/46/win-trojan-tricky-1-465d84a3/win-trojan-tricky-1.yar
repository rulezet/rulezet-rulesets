rule Win_Trojan_Tricky_1
{
strings:
	$a0 = { 81ed0601b90300bf50018db6d90183ef5057b71af3a48d96df018ae7cd21b44efe86d301fe86d301fe86d301fe86d3 }


condition:
	$a0
}
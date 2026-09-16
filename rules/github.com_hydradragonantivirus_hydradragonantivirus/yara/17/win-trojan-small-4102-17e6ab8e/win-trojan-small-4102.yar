rule Win_Trojan_Small_4102
{
strings:
	$a0 = { cd2ae800000000e80b000000ba55????ffeb5153c20800bd0b????ffeb1255555f5b033c }


condition:
	$a0
}
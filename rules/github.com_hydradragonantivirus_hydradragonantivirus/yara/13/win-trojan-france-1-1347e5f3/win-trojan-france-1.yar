rule Win_Trojan_France_1
{
strings:
	$a0 = { 35cd21891e44038c064603b81c25ba4c }


condition:
	$a0
}
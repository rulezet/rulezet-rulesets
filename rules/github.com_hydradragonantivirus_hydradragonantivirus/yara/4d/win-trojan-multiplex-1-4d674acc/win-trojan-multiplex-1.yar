rule Win_Trojan_Multiplex_1
{
strings:
	$a0 = { e80000582d0a01e89502e81403e82402b447b200568d9ced }


condition:
	$a0
}
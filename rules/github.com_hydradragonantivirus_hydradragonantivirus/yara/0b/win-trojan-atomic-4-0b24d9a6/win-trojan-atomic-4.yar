rule Win_Trojan_Atomic_4
{
strings:
	$a0 = { eb00b9eb09ba05feebfc80c43bebf4e82b00e84f00e85f00e87200e85200e85600e86900e89700e89f00e83700e84700e85a00e89d00e9aa00cd20cd20b42acd }


condition:
	$a0
}
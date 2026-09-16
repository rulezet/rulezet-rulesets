rule Win_Trojan_Vundo_25
{
strings:
	$a0 = { 807c24080156eb }

	$a1 = { d47d72c34079 }

	$a2 = { 56c300000000000000000000000000 }


condition:
	$a0 and $a1 and $a2
}
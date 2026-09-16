rule Win_Trojan_IraquiWarrior_2
{
strings:
	$a0 = { 2f90cd21891c90908c44029007ba97 }


condition:
	$a0
}
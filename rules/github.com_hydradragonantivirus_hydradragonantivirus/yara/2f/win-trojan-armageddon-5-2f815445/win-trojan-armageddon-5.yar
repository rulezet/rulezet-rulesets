rule Win_Trojan_Armageddon_5
{
strings:
	$a0 = { 89164a012ea13e018ed8be2a048a04040b880433d22e8b0e3a0181c12a042e8b1e3801b440cd21 }


condition:
	$a0
}
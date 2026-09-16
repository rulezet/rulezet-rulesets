rule Win_Trojan_Chameleon_2
{
strings:
	$a0 = { 0890fcb8d292b9270533d13105902bda2bd8310d474043f84b90e2ed }


condition:
	$a0
}
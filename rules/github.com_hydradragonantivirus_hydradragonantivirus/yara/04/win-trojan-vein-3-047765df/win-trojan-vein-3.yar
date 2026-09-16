rule Win_Trojan_Vein_3
{
strings:
	$a0 = { b903008db6e604bf000157f3a48d96f104b41acd21b44e8d96e004b90700cd217303 }


condition:
	$a0
}
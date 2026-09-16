rule Win_Trojan_Chameleon_8
{
strings:
	$a0 = { 7402fcf8b99104b883cf3105310d90f84b404243474690e2f1 }


condition:
	$a0
}
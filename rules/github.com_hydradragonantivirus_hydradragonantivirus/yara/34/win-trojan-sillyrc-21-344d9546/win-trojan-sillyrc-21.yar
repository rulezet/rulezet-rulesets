rule Win_Trojan_SillyRC_21
{
strings:
	$a0 = { 0d80fc4b7503e80800ea6c01ca1586c4cf505351 }


condition:
	$a0
}
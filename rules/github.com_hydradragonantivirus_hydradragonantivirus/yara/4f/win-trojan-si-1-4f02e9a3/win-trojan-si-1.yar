rule Win_Trojan_SI_1
{
strings:
	$a0 = { b9fd01ba0001b440e8700033c98bd1b80042e86600b90400bab002b440e85b0083fbff7411 }


condition:
	$a0
}
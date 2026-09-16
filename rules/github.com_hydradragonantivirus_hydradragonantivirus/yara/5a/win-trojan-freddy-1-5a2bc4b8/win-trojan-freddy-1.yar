rule Win_Trojan_Freddy_1
{
strings:
	$a0 = { 1f01061000010614008c0616008c0604008c0608008c }


condition:
	$a0
}
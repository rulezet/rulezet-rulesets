rule Win_Trojan_Mutant_4
{
strings:
	$a0 = { d1b80042cd215972065a52b440cd }


condition:
	$a0
}
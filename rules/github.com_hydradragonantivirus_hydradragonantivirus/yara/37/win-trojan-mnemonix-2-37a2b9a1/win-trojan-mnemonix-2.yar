rule Win_Trojan_Mnemonix_2
{
strings:
	$a0 = { 5b83c3199087dbb9ac01b886a52e31074343d1c07a004975f4 }


condition:
	$a0
}
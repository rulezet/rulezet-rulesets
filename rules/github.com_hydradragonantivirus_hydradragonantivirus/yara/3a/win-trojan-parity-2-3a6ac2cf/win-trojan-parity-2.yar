rule Win_Trojan_Parity_2
{
strings:
	$a0 = { 061f0e07fcf3a5b90100bb007cb801039c2eff1e }


condition:
	$a0
}
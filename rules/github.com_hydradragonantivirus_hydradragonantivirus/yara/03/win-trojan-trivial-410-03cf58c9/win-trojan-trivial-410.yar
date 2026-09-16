rule Win_Trojan_Trivial_410
{
strings:
	$a0 = { d8b457b000cd215180e12f80f92c59741e5152b440b9b601ba0001cd217223b457b0015a59 }


condition:
	$a0
}
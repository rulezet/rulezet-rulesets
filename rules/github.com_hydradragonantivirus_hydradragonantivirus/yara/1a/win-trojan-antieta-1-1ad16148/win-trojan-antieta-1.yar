rule Win_Trojan_Antieta_1
{
strings:
	$a0 = { 9c58fba900200f84900066be49544e41b430cd216681fe21415445747d90903c0572779090b8 }


condition:
	$a0
}
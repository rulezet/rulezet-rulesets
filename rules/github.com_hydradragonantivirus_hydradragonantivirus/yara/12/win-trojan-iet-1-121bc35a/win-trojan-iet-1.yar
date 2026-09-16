rule Win_Trojan_Iet_1
{
strings:
	$a0 = { 5e83ee038ccd8bc5488ed88b1e030083eb4e908bd34a50b82e2ecd210bc05874048916030003d8438ec333ff0e1f }


condition:
	$a0
}
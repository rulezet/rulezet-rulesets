rule Win_Trojan_Pantera_II_1
{
strings:
	$a0 = { b90100ba80008bdd81ebaa5581c34d04cd138b87fe0186e02be8b94d048bf583c65d8a86de }


condition:
	$a0
}
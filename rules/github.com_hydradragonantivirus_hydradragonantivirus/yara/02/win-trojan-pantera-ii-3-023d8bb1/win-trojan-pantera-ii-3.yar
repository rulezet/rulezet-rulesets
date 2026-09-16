rule Win_Trojan_Pantera_II_3
{
strings:
	$a0 = { 02b90100ba80008bdd81ebaa5581c35b04cd138b87fe0186e02be8b95b04908bf583c65f908a }


condition:
	$a0
}
rule Win_Trojan_Kiev_4
{
strings:
	$a0 = { 0153b440bad50101dab903008bdfcd215b72 }


condition:
	$a0
}
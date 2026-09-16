rule Win_Trojan_Predator_8
{
strings:
	$a0 = { 02b1c4fa89e5bc372158f7d0d3c850eb01b64c4c4a75f2 }


condition:
	$a0
}
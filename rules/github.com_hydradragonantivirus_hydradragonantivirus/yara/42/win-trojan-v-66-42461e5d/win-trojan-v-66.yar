rule Win_Trojan_V_66
{
strings:
	$a0 = { 3c02f8f3a433c98ed9be8400bf9000 }


condition:
	$a0
}
rule Win_Trojan_Gen_49
{
strings:
	$a0 = { 02cd21b81325baeb01cd218e062d00 }


condition:
	$a0
}
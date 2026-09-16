rule Win_Trojan_Fanthomas_1
{
strings:
	$a0 = { d0bc007ccd12c1e0062d80008ec033db50686000ba8000b90200b80402cd13cb }


condition:
	$a0
}
rule Win_Trojan_SillyIce_3
{
strings:
	$a0 = { c9e87d00b8023d8d940402cd218984e40187dae89000ba }


condition:
	$a0
}
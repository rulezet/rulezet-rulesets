rule Win_Trojan_Bravo_1
{
strings:
	$a0 = { 3e3600504d7422803e32000a7e14c606320000ba1500b91d00bb0100b440cd217207fe063200e8 }


condition:
	$a0
}
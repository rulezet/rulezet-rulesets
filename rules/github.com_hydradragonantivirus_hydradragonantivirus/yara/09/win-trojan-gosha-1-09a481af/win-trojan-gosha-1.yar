rule Win_Trojan_Gosha_1
{
strings:
	$a0 = { 7503e91601e800005e81eeadfb2e807cffff7403e8aa04e800005e81ee46fb2e8c1c2e8c44022e8964fcb4f3cd21 }


condition:
	$a0
}
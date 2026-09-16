rule Win_Trojan_Khizhnjak_34
{
strings:
	$a0 = { 908b1e3704b440cd21e8a5017303e901ffb90000ba00008b1e3704b000b442cd217213ba16 }


condition:
	$a0
}
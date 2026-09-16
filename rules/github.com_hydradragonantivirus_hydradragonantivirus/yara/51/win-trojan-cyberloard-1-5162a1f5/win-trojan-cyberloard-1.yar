rule Win_Trojan_Cyberloard_1
{
strings:
	$a0 = { 0300babd01cd217271b8023dba9e00cd2193b43fb90900bab401cd21beb401bf0001fcf3a6747433c02d0100f8 }


condition:
	$a0
}
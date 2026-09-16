rule Win_Trojan_Peed_208
{
strings:
	$a0 = { 8bc7575059f85a85c333cd77033cc848c1c1cd50 }


condition:
	$a0
}
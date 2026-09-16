rule Win_Trojan_Kela_5
{
strings:
	$a0 = { b9d809b440e826fec3b8024233c933d2e81bfec3b8004233c933d2e810fec3b80057e809fe }


condition:
	$a0
}
rule Win_Trojan_L_19
{
strings:
	$a0 = { eb2890e81000b420d0e4b91901ba0001cd21e80100c3be2f01b9ea00a02a01300446e2fbc30000000000ba }


condition:
	$a0
}
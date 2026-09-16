rule Win_Trojan_E_39
{
strings:
	$a0 = { 83ef038a07040188073c5a76dbff75fc }


condition:
	$a0
}
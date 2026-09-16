rule Win_Trojan_Gullich_2
{
strings:
	$a0 = { 33c08ed0bc007bfb52561e2ea0447cbb6a7cb9470136300743e2fa }


condition:
	$a0
}
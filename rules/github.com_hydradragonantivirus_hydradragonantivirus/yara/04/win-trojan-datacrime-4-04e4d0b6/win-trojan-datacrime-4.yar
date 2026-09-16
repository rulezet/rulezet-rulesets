rule Win_Trojan_Datacrime_4
{
strings:
	$a0 = { b402cd2143fec975f1bbb101b500ba80 }


condition:
	$a0
}
rule Win_Trojan_Ascii_61_160_232_199_1
{
strings:
	$a0 = { 36312e3136302e3233322e313939 }


condition:
	$a0
}
rule Win_Trojan_Whale_27
{
strings:
	$a0 = { 020033de81f676185b5e81eb9f23b9 }


condition:
	$a0
}
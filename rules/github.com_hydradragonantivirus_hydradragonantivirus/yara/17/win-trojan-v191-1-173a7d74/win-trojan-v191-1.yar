rule Win_Trojan_V191_1
{
strings:
	$a0 = { 0b018bacbc0181c503018d94be0133c9b4 }


condition:
	$a0
}
rule Win_Trojan_Kuluoz_39
{
strings:
	$a0 = { c745f8990ad6fdc745dcb2f340fdc745d466a573f5 }


condition:
	$a0
}
rule Win_Trojan_Formas_1
{
strings:
	$a0 = { 8b1e8401cd218b1e8901891e900158503d0100740eb4408b1e8401b90300ba8f01cd21e83a00 }


condition:
	$a0
}
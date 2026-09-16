rule Win_Trojan_Grog_7
{
strings:
	$a0 = { ad50b9ef0eac5e81c61e018ad0ac2ac2fec28844ff47e2f5c36172267e8a88813a708294849262328071440448 }


condition:
	$a0
}
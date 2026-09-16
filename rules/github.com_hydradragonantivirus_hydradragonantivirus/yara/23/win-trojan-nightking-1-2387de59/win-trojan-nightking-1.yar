rule Win_Trojan_Nightking_1
{
strings:
	$a0 = { 03ba8001b9020033dbcd130e07bb2007e8a700e8110007b85003ba8001b90200bb0110cd13eb }


condition:
	$a0
}
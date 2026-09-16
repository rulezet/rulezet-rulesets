rule Win_Trojan_Enola_1
{
strings:
	$a0 = { 012eff360c01fca5a5a5a5a5a5a5803edd01ff }


condition:
	$a0
}
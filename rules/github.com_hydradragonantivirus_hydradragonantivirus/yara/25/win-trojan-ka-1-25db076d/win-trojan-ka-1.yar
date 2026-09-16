rule Win_Trojan_KA_1
{
strings:
	$a0 = { 51525657505380fc4b7509e86a02e81b00e8640280fcff75045b2bdb535b585f5e5a599d2eff2e8f02b003cf }


condition:
	$a0
}
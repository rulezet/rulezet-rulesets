rule Win_Trojan_Cordura_1
{
strings:
	$a0 = { a3e4022ea2e6022ea37103b419cd210441b4472ea2e70233d22e8a16e7028d362903cd21b40e2e8a16e702cd21 }


condition:
	$a0
}
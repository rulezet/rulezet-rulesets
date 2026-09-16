rule Win_Trojan_Ramm_1
{
strings:
	$a0 = { 696e3935005c57696e3938000f5c57696e2e696e69005c72616d6d2e6578650072756e }


condition:
	$a0
}
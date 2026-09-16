rule Win_Trojan_Gaertob_1
{
strings:
	$a0 = { 756767633a2f2f6c75726572732d616e7468656d2e6e6c2f745f776f726d2e706870 }


condition:
	$a0
}
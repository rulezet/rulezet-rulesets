rule Win_Trojan_Headless_1
{
strings:
	$a0 = { 905052ac0ac0740b86d080ea5db402cd21ebf0585ac3528ac2b9ff0033d2bba701cd2683c402 }


condition:
	$a0
}
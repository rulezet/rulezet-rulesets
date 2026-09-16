rule Win_Trojan_Future_1
{
strings:
	$a0 = { 0601e89a0a2ec687850c002ec687860c002e80bf830c027403eb29901e0e078cd80510002e0187670d2e8b8767 }


condition:
	$a0
}
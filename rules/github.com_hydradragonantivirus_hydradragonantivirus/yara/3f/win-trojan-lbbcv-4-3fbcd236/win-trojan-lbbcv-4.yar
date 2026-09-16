rule Win_Trojan_LBBCV_4
{
strings:
	$a0 = { 33c08ed08ed88ec0bc007cfbb106a11304d3e02de0078ec0832e130404 }


condition:
	$a0
}
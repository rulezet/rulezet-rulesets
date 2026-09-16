rule Win_Trojan_Agent_35438
{
strings:
	$a0 = { 32c07404de09cdb5535683c4046813f71d2783c4048b5c24fc83c4048b5c24 }


condition:
	$a0
}
rule Win_Trojan_Chukcha_2
{
strings:
	$a0 = { 408b1e74018b0e72018d16d303cd21b43e8b1e7401cd21 }


condition:
	$a0
}
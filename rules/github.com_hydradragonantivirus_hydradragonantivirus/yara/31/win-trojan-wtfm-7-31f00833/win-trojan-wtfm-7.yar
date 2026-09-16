rule Win_Trojan_Wtfm_7
{
strings:
	$a0 = { e9383e81f10aaae809007316e8b6003d7056a0cd21c35f2ae480f47332254757ebf1be790e81ee }


condition:
	$a0
}
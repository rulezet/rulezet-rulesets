rule Win_Trojan_Wtfm_3
{
strings:
	$a0 = { c35fb43f80c42032254757ebf1be637581eec974b95b8d81e9378c390c723bb866f72d060d39 }


condition:
	$a0
}
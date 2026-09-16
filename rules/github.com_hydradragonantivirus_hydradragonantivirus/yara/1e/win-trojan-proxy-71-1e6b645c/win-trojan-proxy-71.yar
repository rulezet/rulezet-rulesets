rule Win_Trojan_Proxy_71
{
strings:
	$a0 = { 5203d0baf774b5635a81c1218aeef578005933cbb8e76a3e7d8b15e82e41000f6efe81eec75adc277600bebff14fe60f6ec4 }


condition:
	$a0
}
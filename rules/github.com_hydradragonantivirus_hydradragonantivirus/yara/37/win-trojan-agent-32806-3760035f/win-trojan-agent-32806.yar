rule Win_Trojan_Agent_32806
{
strings:
	$a0 = { b7c128ebf2654f9b574834fa281ee23ecc20c659f96ab80873fe19cdf51a74ee7150cf29a15365fbb6bb78a07f536d131c20ae7cb8723b63a222bca7ef3b65bdc5 }


condition:
	$a0
}
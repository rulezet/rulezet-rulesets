rule PKCS_DigestDecoration_SHA512__8_byt_19_
{
strings:
	$a0 = { 3051300d060960864801650304020305000440 }

condition:
	$a0
}
rule PKCS_DigestDecoration_SHA384__8_byt_19_
{
strings:
	$a0 = { 3041300d060960864801650304020205000430 }

condition:
	$a0
}
rule Win_Trojan_Amz_3
{
strings:
	$a0 = { 1e068cc88ed82eff06aa03908cc82b0693038b1e8f0303d8891e5b038b1e8b0303d8891e6d038b1e9103891e5903 }


condition:
	$a0
}
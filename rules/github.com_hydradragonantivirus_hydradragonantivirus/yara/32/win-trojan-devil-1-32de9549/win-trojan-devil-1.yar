rule Win_Trojan_DEVIL_1
{
strings:
	$a0 = { b8010333dbcd1332f6b90d00bb0002b80103cd13e8a70032d2b8010233db8ec3bb007ccd13 }


condition:
	$a0
}
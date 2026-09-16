rule Win_Trojan_Virut_215
{
strings:
	$a0 = { fce82800000053b9a20d00008bda6631104086d6408d1413e2f45bc3 }


condition:
	$a0
}
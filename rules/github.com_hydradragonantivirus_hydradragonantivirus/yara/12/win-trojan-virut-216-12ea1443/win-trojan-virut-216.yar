rule Win_Trojan_Virut_216
{
strings:
	$a0 = { fce82900000053b9a00d00008bda6631104086d6408d1413e2f45bc3 }


condition:
	$a0
}
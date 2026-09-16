rule Win_Trojan_VGEN_644
{
strings:
	$a0 = { 6101e84f00b408cd213c59740e3c79740a3c4e742a3c6e7426ebeae83b00b601b90100e82300b6008b0ecd03e81a00 }


condition:
	$a0
}
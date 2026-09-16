rule Win_Trojan_VGEN_257
{
strings:
	$a0 = { 09ba3201cdffff21cd204e6f7420656e6f756768206d65ffff6d6f727924fd8cdb5383c32d03da8ccdffff8bc280 }


condition:
	$a0
}
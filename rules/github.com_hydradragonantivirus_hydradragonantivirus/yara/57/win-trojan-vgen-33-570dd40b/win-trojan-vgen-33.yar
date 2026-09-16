rule Win_Trojan_Vgen_33
{
strings:
	$a0 = { 33dbe800005e83ee078cc02e0384a502051000502effb4a3021e0efaf7dcf7dcfb33c08ed8a18400a3c800a18600 }


condition:
	$a0
}
rule Win_Trojan_Magistr_11
{
strings:
	$a0 = { 720000b1aff807b0502be90eaf46dee7531fedfc97ab973b3efb9426bb226e89e02a439e2ece64d69df4fb8f98719a9969a9a25bfe4f809484021e06db0eafc3eea58b }


condition:
	$a0
}
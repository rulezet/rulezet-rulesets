rule Win_Trojan_VGEN_581
{
strings:
	$a0 = { 5e5756a5a5a45f57c64505005e83ee03061e92b2608ec233ff26803de8742257b9f80090f3a41fbe8400a5a50e1f }


condition:
	$a0
}
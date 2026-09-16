rule Win_Trojan_PS_13
{
strings:
	$a0 = { be000189f7c704????c64402??56b93402ad35????d1c8abe2f7 }


condition:
	$a0
}
rule Win_Trojan_PS_12
{
strings:
	$a0 = { be000189f7c704????c64402??56b9ac01ad35????d1c8abe2f7c3 }


condition:
	$a0
}
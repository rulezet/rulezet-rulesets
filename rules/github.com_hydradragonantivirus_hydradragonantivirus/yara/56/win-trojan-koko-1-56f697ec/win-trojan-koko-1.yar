rule Win_Trojan_Koko_1
{
strings:
	$a0 = { 1372db33f6b9fe008b841d0386c489841d034646e2f2b8c1c02ea31b05b80103b90100cd13 }


condition:
	$a0
}
rule Win_Trojan_Bancos_1843
{
strings:
	$a0 = { e91f49a7e8ca8fe20de09703782f29ad3f5b282c91a30f9a21bf8ed21b0f17bfc9827308efb2cb62b5a9e5d4a2b048e258f642923714c3bf3c65e4c53769fac0735d9b12a55d }


condition:
	$a0
}
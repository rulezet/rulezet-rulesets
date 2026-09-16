rule Win_Trojan_Zlob_2178
{
strings:
	$a0 = { e4a50000746546696c65410044656c6500000000e4d2dac7f5dcc1fec6dfc7dac3dfd6fcd1d9d6d0c7c00000e4d2dac7f5dcc1e0daddd4dfd6fcd1d9d6d0c7002564 }


condition:
	$a0
}
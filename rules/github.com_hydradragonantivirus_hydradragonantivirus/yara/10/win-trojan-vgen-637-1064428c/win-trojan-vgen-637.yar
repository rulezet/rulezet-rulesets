rule Win_Trojan_VGEN_637
{
strings:
	$a0 = { 56b8cdabcd213dffff7424be8000bf40008a0c32ed4141fcf3a45e0e1fbf0001065781ef8d008bc7b9f81bfcf3 }


condition:
	$a0
}
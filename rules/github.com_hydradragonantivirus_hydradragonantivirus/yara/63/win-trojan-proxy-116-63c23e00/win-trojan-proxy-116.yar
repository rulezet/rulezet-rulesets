rule Win_Trojan_Proxy_116
{
strings:
	$a0 = { c800000060837d0c010f85f2070000e8000000005866b8a62097 }

	$a1 = { 746d702e646c6c }


condition:
	$a0 and $a1
}
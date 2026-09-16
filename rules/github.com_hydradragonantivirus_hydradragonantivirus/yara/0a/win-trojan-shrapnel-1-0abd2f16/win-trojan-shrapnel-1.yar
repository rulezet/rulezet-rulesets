rule Win_Trojan_Shrapnel_1
{
strings:
	$a0 = { 16cd2f0ac074023c80c3a113042d0700a31304b106d3e050072bdb0e1f2ae42bd2cd1380beef }


condition:
	$a0
}
rule Win_Trojan_Heiko_1
{
strings:
	$a0 = { 2e8c9ef103fc80d24e0e9b80ee1e0e4a80c20a1f4280f60707f980fa738986eb03fd80c668899eed03 }


condition:
	$a0
}
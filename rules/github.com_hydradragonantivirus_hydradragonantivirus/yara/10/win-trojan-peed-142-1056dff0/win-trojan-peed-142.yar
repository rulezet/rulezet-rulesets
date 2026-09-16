rule Win_Trojan_Peed_142
{
strings:
	$a0 = { f7da87fa750c5589e5ad83ee0546c9c20800e800000000ba0400000087d181c47b2f000081ec772f0000 }


condition:
	$a0
}
rule Win_Trojan_Peed_235
{
strings:
	$a0 = { f7d2917418f7db29dff7db01de89c3eb2c5589e5ad83ee0546c9c20800e84900000083c40283c402bf }


condition:
	$a0
}
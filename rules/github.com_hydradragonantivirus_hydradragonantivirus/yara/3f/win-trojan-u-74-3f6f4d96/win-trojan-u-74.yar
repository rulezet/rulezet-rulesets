rule Win_Trojan_U_74
{
strings:
	$a0 = { 68616c74207d207c202e6463632073656e6420246e69636b20 }


condition:
	$a0
}
rule Win_Trojan_ImpotentG_1
{
strings:
	$a0 = { 81ed0b018986160433ffc7454a00008ec7be9600 }


condition:
	$a0
}
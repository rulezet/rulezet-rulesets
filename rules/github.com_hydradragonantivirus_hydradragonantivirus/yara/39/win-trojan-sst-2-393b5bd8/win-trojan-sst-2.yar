rule Win_Trojan_SST_2
{
strings:
	$a0 = { 8b0c80e1e080c1078b5402a1d101cd218a26cd01cd21a1ce018b0ed301ba9e00cd218a26cc01 }


condition:
	$a0
}
rule Win_Trojan_Zim_1
{
strings:
	$a0 = { 8ed0bc007c8ed8fbcd138ec08bf4e8ec0006b85a0550cba14c00a36000a14e00a36200c7064c00d4058c064e00 }


condition:
	$a0
}
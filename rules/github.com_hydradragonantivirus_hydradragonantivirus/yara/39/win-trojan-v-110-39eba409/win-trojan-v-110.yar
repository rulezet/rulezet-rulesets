rule Win_Trojan_V_110
{
strings:
	$a0 = { 0133f6bf00f0f3a4a16504a36704baa601b82425cd21b419cd21a28a04b200b447be9804cd21cd1132e424c0b906 }


condition:
	$a0
}
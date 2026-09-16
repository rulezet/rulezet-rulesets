rule Win_Trojan_Doser_1
{
strings:
	$a0 = { 56100000e7ffffffffbc090f3ffff6dc5702e70aec733e88a44e0f3fffb80107ffff658a944c0f3fff8ca4560f3fff6557654185d585c36532c165f6cf654f82c301e1ea8aa44e0f3fffea097246ffffffff8f8f8f8f }


condition:
	$a0
}
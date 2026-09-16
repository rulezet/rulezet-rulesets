rule Win_Trojan_TaiPan_7
{
strings:
	$a0 = { 4f4e453e5250b80057cd66890eb7008916b900b440b9cd0233d2cd66b440b90a00bae502cd66 }


condition:
	$a0
}
rule Win_Trojan_TaiPan_6
{
strings:
	$a0 = { 069802a3af00a19602a3ad0016582d10008ec08ed8 }


condition:
	$a0
}
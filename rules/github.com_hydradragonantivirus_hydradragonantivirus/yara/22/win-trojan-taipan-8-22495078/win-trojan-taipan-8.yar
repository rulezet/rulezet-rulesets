rule Win_Trojan_TaiPan_8
{
strings:
	$a0 = { 5e83ee03cd213dcf7b7517b90a000e1f81c6f701fc }


condition:
	$a0
}
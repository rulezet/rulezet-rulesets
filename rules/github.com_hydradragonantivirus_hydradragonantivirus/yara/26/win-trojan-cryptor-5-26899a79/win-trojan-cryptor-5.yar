rule Win_Trojan_Cryptor_5
{
strings:
	$a0 = { 50c377423de803723d2d03008986ab038db651028dbe6d1033c0b91c0ee8a90b8bf703f983c710 }


condition:
	$a0
}
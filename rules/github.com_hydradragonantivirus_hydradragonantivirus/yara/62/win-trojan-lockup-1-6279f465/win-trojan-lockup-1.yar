rule Win_Trojan_Lockup_1
{
strings:
	$a0 = { 0a8bd7b8003dcd218bd8b002e8cf0550b43ecd21582e8026250100e8400a72062e800e250101e831087303e98000 }


condition:
	$a0
}
rule Win_Trojan_Delf_996
{
strings:
	$a0 = { 5b595dc3ffffffff0d0000005379734f7074696f6e2e62696e0000005356e8670033288bda8bf08bc6e86717ee8c8d4630e867 }


condition:
	$a0
}
rule Win_Trojan_Whale64A_1
{
strings:
	$a0 = { e81d00f8fb742d908cc353f8598ed9e8 }


condition:
	$a0
}
rule Win_Trojan_Trojan_249
{
strings:
	$a0 = { 0ebe7301b961042e301446e2fa90e60e0e538fe30d0fb64c4fc32f333f2d7a56100882ce4680d68f200d0e9b0e8f20 }


condition:
	$a0
}
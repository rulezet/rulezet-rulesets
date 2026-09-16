rule Win_Trojan_Stealthie_1
{
strings:
	$a0 = { e800005e83ee030e1f8cc08984????b002e6219c5825fffe509d065633c08ec081c6b50abff004b90f00fcf3aa56b8aaaacd21bff0045eb90f00f3a65e07 }


condition:
	$a0
}
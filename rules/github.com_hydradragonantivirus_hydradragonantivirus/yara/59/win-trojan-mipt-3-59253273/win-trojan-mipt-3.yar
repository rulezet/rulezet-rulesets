rule Win_Trojan_MIPT_3
{
strings:
	$a0 = { b95a0290ba04010e1fe8c1007221b80042b90000ba00 }


condition:
	$a0
}
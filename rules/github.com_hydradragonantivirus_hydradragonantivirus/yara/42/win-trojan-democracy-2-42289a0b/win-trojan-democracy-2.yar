rule Win_Trojan_Democracy_2
{
strings:
	$a0 = { e86e018cd80510002e010656092e01065809b88c09e8a900e869019dfa2e8e1658092e8b265a09fbea000000000000 }


condition:
	$a0
}
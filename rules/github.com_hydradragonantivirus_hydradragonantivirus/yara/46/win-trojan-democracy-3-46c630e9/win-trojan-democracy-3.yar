rule Win_Trojan_Democracy_3
{
strings:
	$a0 = { 8cd80510002e0106a8092e0106aa09b8de09e8a900e87c019dfa2e8e16aa092e8b26ac09fbea000000000000 }


condition:
	$a0
}
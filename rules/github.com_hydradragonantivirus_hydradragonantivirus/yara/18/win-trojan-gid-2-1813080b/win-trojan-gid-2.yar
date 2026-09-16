rule Win_Trojan_GID_2
{
strings:
	$a0 = { 8a6bb17effd8060bc97f03418103f12bc17213041f40c6ee7d0233c93bae5cc1068bc1579257 }


condition:
	$a0
}
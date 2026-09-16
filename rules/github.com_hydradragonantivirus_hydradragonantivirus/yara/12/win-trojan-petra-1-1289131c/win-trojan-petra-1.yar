rule Win_Trojan_Petra_1
{
strings:
	$a0 = { 088adaa97effd8060bc97f03509103f12bc17213041f40c6ee7d0233c93bde62c1068bc1eb3ec1 }


condition:
	$a0
}
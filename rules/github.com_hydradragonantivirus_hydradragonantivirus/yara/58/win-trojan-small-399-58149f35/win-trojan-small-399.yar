rule Win_Trojan_Small_399
{
strings:
	$a0 = { 256c75000d0ac9cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdbb0d0aba205468657461203220286329 }


condition:
	$a0
}
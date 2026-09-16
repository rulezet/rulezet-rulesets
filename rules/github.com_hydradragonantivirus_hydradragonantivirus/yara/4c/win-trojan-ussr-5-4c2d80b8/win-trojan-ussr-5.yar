rule Win_Trojan_USSR_5
{
strings:
	$a0 = { 06065633d2b483cd215e5681fa9019 }


condition:
	$a0
}
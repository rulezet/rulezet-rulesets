rule Win_Trojan_Trojan_203
{
strings:
	$a0 = { febacf00bd8f15817600510245454a75f6 }


condition:
	$a0
}
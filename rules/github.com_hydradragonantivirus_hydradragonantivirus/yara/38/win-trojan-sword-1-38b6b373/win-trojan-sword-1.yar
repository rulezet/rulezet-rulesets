rule Win_Trojan_Sword_1
{
strings:
	$a0 = { 2135cd21891ebc028c06be02b82125bab302cd211f8cd8 }


condition:
	$a0
}
rule Win_Trojan_Manzon_2
{
strings:
	$a0 = { e800008bec8b760081ee5605b95305e80c0058c3be0301b95305e80100c32e8034 }


condition:
	$a0
}
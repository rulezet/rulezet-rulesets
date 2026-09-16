rule Win_Trojan_Yakes_20
{
strings:
	$a0 = { 5c4d6f746f72204c6966655c526f746f722e706462 }


condition:
	$a0
}
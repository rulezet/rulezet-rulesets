rule Win_Trojan_Nova_2
{
strings:
	$a0 = { 7cfa33db8edb8ed38be6fb5356b370c6474ffffc8b47dc8944028b47de894404ff8fa303cd12 }


condition:
	$a0
}
rule Win_Trojan_Peterburg_1
{
strings:
	$a0 = { cd218c06ff02891efd02078b1627 }


condition:
	$a0
}
rule Win_Trojan_Grog_16
{
strings:
	$a0 = { 14908bf48b34b9e90180047e802c66e201c346ebf4e8ea }


condition:
	$a0
}
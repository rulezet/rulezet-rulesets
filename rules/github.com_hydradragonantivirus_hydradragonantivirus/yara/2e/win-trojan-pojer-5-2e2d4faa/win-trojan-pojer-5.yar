rule Win_Trojan_Pojer_5
{
strings:
	$a0 = { 1e5150f8e800005ef883ee09bb240003def82e8a944d07f8b9f6062e3017f843e2f9 }


condition:
	$a0
}
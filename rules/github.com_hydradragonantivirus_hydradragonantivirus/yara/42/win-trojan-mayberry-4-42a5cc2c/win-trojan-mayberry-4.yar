rule Win_Trojan_Mayberry_4
{
strings:
	$a0 = { 0300cd2000baf700bb16012e8137000043434a75f6 }


condition:
	$a0
}
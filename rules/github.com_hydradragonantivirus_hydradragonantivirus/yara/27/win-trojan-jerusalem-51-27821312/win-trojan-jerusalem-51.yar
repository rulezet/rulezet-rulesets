rule Win_Trojan_Jerusalem_51
{
strings:
	$a0 = { b4e0cd2180fce0731680fc037211b4 }


condition:
	$a0
}
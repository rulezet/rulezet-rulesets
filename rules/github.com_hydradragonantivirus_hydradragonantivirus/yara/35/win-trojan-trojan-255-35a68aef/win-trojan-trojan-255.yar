rule Win_Trojan_Trojan_255
{
strings:
	$a0 = { 38018a2f322e0301882f4381fb00097ef159c3 }


condition:
	$a0
}
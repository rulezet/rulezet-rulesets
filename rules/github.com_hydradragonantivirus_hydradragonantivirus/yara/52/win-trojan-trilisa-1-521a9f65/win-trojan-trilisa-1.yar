rule Win_Trojan_Trilisa_1
{
strings:
	$a0 = { 686f73742e65786500686f73742e736372 }


condition:
	$a0
}
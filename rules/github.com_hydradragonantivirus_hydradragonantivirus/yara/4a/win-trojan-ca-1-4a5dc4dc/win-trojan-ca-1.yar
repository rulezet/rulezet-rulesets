rule Win_Trojan_CA_1
{
strings:
	$a0 = { bf9701bb34012e813746f583c3024f75f5eb0ae8010000c6061f00c3c3 }


condition:
	$a0
}
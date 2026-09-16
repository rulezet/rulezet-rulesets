rule Win_Trojan_Tiny_27
{
strings:
	$a0 = { 5a01960e59f3a4ba5401b44ecd217301cbb8023d99b29ecd2193b43fba5a015459cd21055a0050 }


condition:
	$a0
}
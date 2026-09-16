rule Win_Trojan_Mini_62
{
strings:
	$a0 = { ba9e00cd2193b43fba4e01908bcccd21054e0090502bc9f7e1b442cd2159b4405a52cd21b4 }


condition:
	$a0
}
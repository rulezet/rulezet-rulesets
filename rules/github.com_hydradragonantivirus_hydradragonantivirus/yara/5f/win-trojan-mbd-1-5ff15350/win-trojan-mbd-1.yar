rule Win_Trojan_Mbd_1
{
strings:
	$a0 = { f581c6ea04b9c1041e33c08ed8eb02eb1566c706fc038034 }


condition:
	$a0
}
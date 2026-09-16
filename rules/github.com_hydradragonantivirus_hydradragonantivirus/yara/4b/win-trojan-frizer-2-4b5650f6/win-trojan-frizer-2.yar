rule Win_Trojan_Frizer_2
{
strings:
	$a0 = { 218b162502b9a00281c20101061f89163202b43fcd2103d152b800429933c9cd21b44059ba0001 }


condition:
	$a0
}
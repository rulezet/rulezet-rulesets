rule Win_Trojan_Mothership_1
{
strings:
	$a0 = { ad4bcd213dad2b7402f8c3f9c3b42bcf3dad4b74f83d00 }


condition:
	$a0
}
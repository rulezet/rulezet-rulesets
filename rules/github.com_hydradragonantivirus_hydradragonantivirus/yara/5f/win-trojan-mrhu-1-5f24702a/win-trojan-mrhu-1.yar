rule Win_Trojan_MrHu_1
{
strings:
	$a0 = { c7073e7cfb31c0cd13b106be1304ff0cadd3e0a3937cb90f4fba00018ec0b8010231dbcd13 }


condition:
	$a0
}
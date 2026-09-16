rule Win_Trojan_SeventhSon_4
{
strings:
	$a0 = { fe73253de803762050b91c01b440cd21 }


condition:
	$a0
}
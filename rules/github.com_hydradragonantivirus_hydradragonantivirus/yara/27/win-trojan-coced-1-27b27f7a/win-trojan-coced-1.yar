rule Win_Trojan_Coced_1
{
strings:
	$a0 = { 75626a6563743a208843723d79703f4b7584f662812eed78ca10cdd121edf10175647773 }


condition:
	$a0
}
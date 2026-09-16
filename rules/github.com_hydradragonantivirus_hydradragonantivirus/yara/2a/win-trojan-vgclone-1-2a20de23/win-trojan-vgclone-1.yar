rule Win_Trojan_Vgclone_1
{
strings:
	$a0 = { 58f49f6516b7ae618dde8a14ad911632ac618d3f18ecfc1586ac16acad618df4155aac1686ae618d }


condition:
	$a0
}
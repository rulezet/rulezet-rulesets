rule Win_Trojan_Treb_3
{
strings:
	$a0 = { 1c00b440cd21c33dcabe7504b8554acf3d004b741d2eff }


condition:
	$a0
}
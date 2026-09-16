rule Win_Trojan_Vesna_10
{
strings:
	$a0 = { ac00f820eb071a25552ccee323ce5426213947edac00c620eb07af38b4279c6a21ac00f920eb079c }


condition:
	$a0
}
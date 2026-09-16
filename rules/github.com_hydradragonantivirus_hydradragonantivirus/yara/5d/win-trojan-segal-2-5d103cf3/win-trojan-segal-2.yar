rule Win_Trojan_Segal_2
{
strings:
	$a0 = { cd210ae474511eb448bb2500cd2173128cd8488ed8b44a8b1e030083eb26cd21ebe5508ec0488ed8c706010008 }


condition:
	$a0
}
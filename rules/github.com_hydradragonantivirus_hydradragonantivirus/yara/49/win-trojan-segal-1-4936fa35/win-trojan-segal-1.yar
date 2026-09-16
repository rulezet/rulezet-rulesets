rule Win_Trojan_Segal_1
{
strings:
	$a0 = { cd210ae474511eb448bb2300cd2173128cd8488ed8b44a8b1e030083eb24cd21ebe5508ec0488ed8c706010008 }


condition:
	$a0
}
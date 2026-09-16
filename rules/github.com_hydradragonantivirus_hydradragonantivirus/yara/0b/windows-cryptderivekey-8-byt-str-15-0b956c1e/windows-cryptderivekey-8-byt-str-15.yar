rule Windows_CryptDeriveKey__8_byt_STR_15_
{
strings:
	$a0 = { 43727970744465726976654b657900 }

condition:
	$a0
}
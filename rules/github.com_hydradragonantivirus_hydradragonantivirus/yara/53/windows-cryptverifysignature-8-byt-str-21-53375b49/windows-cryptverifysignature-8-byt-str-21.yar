rule Windows_CryptVerifySignature__8_byt_STR_21_
{
strings:
	$a0 = { 43727970745665726966795369676e617475726500 }

condition:
	$a0
}
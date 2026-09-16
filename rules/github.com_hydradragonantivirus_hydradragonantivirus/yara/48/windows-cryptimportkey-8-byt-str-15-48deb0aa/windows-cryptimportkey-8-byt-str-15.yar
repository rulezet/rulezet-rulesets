rule Windows_CryptImportKey__8_byt_STR_15_
{
strings:
	$a0 = { 4372797074496d706f72744b657900 }

condition:
	$a0
}
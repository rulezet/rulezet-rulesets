rule Win_Trojan_Crypt_226
{
strings:
	$a0 = { 32c07408870bb9409d2bbd4e57535b0f03fe53538b7c240883c40ce96607 }


condition:
	$a0
}
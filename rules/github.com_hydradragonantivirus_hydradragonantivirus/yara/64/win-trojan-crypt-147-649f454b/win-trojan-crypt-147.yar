rule Win_Trojan_Crypt_147
{
strings:
	$a0 = { 81c5????????(01|29|31)(28|29|1a|2b|2e|2f)81ed[0-20]3b(c5|cd|d5|dd|f5|fd)0f82??ffffff }


condition:
	$a0
}
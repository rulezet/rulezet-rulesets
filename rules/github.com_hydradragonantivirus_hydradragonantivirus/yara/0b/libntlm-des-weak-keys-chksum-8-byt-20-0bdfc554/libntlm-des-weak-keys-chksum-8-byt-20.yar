rule libntlm_DES_weak_keys_chksum__8_byt_20_
{
strings:
	$a0 = { d0cf073893708a837dd78a3665296c1f7c3fd341 }

condition:
	$a0
}
rule openbsd_hw_c_do_digest_md5zero__8_byt_16_
{
strings:
	$a0 = { d41d8cd98f00b204e9800998ecf8427e }

condition:
	$a0
}
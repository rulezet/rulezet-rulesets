rule Win_Trojan_Lineage_52
{
strings:
	$a0 = { 5449e1f7d1d836cef11bcc404523e63dc3eed98d7f54161dd2b587e81f828644164fe70c03bcf1cc964d30bcb1b875cc8932675d7ebb1ed18c74b1f8788d67a4e1bcb2d45e11f45ea805fb12186b92ca }


condition:
	$a0
}
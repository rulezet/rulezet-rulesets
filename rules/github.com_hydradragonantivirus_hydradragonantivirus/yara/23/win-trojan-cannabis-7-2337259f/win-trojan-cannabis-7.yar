rule Win_Trojan_Cannabis_7
{
strings:
	$a0 = { 33c08ed88ed0bc007cbb587da14c0039d8742da3af7da14e00a3b17dbf00048b451348894513b106d3e02dc0078e }


condition:
	$a0
}
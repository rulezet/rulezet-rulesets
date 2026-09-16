rule Win_Trojan_DenZuk_9
{
strings:
	$a0 = { fa8cc88ed88ed0bc00f0fbb8787c50c3 }


condition:
	$a0
}
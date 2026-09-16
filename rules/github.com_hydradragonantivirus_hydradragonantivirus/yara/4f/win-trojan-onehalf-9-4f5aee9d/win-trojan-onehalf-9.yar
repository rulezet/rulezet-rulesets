rule Win_Trojan_OneHalf_9
{
strings:
	$a0 = { 87a78477e3b8f105a08834bbefe2b9eba8b41eef379b24c2e0878bc6499ce7c8e7e6576462ef3346d177f866cc35a45e }


condition:
	$a0
}
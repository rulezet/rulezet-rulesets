rule Win_Trojan_ASP_20
{
strings:
	$a0 = { 757365725c[0-12]5cb3ccd0f25cb8bdbcfe[0-46]bcc7cac2b1be2e6c6e6b[0-130]64656c20633a5c612e6c6e6b }


condition:
	$a0
}
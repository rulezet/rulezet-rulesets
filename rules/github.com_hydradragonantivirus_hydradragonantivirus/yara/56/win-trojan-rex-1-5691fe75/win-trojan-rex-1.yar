rule Win_Trojan_Rex_1
{
strings:
	$a0 = { 06bc0700fe06bd07803ebd070f7558c606bd0701a113042d0200a31304c1e006068ec0b8040233 }


condition:
	$a0
}
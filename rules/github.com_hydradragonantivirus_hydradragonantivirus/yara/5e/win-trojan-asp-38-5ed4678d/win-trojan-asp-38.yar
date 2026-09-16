rule Win_Trojan_ASP_38
{
strings:
	$a0 = { 736f757263653d2226656a28222f6c702e7261722229 }

	$a1 = { 6d6964287a722c692c31293d225c22 }


condition:
	$a0 and $a1
}
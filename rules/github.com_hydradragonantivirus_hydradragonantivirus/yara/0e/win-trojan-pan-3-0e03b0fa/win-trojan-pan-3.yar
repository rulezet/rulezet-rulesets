rule Win_Trojan_Pan_3
{
strings:
	$a0 = { 389b5e1b91ce9fdf3e8f980507ee05cda7279c33e70aefc52c2f3031691dbd0a04f7f7d13a3b61be }


condition:
	$a0
}
rule Win_Trojan_Bancos_873
{
strings:
	$a0 = { c059530c1eedb2b22bfe902e01a4b9c1d9fdc785ff61adeeebce4d819563969c0e41bd1e5c8b0d707c6b9e03d70b7458053d079ef6b24e8cddeaefa7cd5b3f3e0f }


condition:
	$a0
}
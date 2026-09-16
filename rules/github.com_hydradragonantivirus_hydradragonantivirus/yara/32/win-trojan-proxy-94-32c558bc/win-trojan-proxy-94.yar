rule Win_Trojan_Proxy_94
{
strings:
	$a0 = { e80100bd54cc6a0c6848064100e80100bcfc8365e4008b750c8bc60faf45100145088365fc00ff4d10780b2975088b4d08ff5514ebf0 }


condition:
	$a0
}
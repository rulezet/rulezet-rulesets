rule Win_Trojan_Bancos_1794
{
strings:
	$a0 = { b9f5a42539bde9241811492ef246089d96adf99562f9b6d196ec1e8aa14beafa30c35d0253d0c1f5f6b77407af15b6deb31705803e7d18504a35ef3afd485fe461cc3ca5875e }


condition:
	$a0
}
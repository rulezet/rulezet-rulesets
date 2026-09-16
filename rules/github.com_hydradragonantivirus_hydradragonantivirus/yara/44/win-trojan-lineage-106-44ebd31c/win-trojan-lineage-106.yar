rule Win_Trojan_Lineage_106
{
strings:
	$a0 = { 89aa4afdbfda02f5c4dd2cda0880f2bd1249cce2157772424de7dfe483345a0f13d8a5624dcca2c04b8be55f3ba3bcac093aa917f0055a7b3c87f27029cf8cac786b3fa1 }


condition:
	$a0
}
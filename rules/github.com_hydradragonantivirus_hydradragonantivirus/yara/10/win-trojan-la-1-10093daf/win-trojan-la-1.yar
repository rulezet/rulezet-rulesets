rule Win_Trojan_LA_1
{
strings:
	$a0 = { 8bd5b91d039c3eff9e270172a7b8004233c98bd19c3eff9e2701b4408bd581c21d03b90a009c }


condition:
	$a0
}
rule Win_Trojan_Hitchcock_1
{
strings:
	$a0 = { 4a4503e88ec545268916030026892e010026c6060000 }


condition:
	$a0
}
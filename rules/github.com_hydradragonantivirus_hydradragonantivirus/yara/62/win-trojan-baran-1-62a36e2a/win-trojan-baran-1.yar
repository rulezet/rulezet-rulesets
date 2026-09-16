rule Win_Trojan_Baran_1
{
strings:
	$a0 = { 561dc7c4107b5527c38c8ce300a2e2b62ee86f68a8bf981a }


condition:
	$a0
}
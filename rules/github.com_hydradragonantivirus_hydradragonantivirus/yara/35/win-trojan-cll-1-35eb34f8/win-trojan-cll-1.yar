rule Win_Trojan_CLL_1
{
strings:
	$a0 = { 02f7f140895402894404c7044d5ab8004233c98bd1cd21720db80040b92000ba5303cd217200 }


condition:
	$a0
}
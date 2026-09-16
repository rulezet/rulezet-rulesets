rule Win_Trojan_Lubak_1
{
strings:
	$a0 = { d8bf640089855702bb00018a8593028b8d94022e88072e894f01b42fcd218c858902899d8b02b41aba590203d7 }


condition:
	$a0
}
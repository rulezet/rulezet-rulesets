rule Win_Trojan_Bancos_1485
{
strings:
	$a0 = { 687474703a2f2f }

	$a1 = { 43617274616f2e657865 }

	$a2 = { 633a5c54656d705c43617274616f2e657865 }


condition:
	$a0 and $a1 and $a2
}
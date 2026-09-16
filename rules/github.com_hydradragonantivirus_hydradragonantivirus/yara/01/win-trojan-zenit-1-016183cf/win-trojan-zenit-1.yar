rule Win_Trojan_Zenit_1
{
strings:
	$a0 = { dc005589e5b800069a3005dc0081ec0006bf00000e57b8200050bf52011e579a0000ba00833ee423007403e9b0 }


condition:
	$a0
}
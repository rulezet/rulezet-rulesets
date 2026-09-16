rule Win_Trojan_Suriv1_2
{
strings:
	$a0 = { b42acd218af9c407720d81fa020874027205c6061e02 }


condition:
	$a0
}
rule Win_Trojan_Hybris_6
{
strings:
	$a0 = { 4000812bfdfeba4981c3040000004f75f168a8584000c300000000 }


condition:
	$a0
}
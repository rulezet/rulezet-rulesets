rule Win_Trojan_Vacsina_5
{
strings:
	$a0 = { 2e890e0800b8014380e1fecd217303e9c801b8023d8e5e0e }


condition:
	$a0
}
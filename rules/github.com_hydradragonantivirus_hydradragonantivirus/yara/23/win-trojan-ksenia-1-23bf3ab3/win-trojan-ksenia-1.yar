rule Win_Trojan_Ksenia_1
{
strings:
	$a0 = { 02ebeae81c016a001fbe840066ff348d86f70c0e50668f04b4b4cd2181fa01fa742e585b5a66 }


condition:
	$a0
}
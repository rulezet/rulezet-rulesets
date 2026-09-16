rule Win_Trojan_CmosKiller_1
{
strings:
	$a0 = { ff0088c8e670e671e2f8cd20 }


condition:
	$a0
}
rule Win_Trojan_XWG_1
{
strings:
	$a0 = { fa5300721881fa9c00720c81faa000720c81faf504730634ccb103d2c8aa59e2db071fc350 }


condition:
	$a0
}
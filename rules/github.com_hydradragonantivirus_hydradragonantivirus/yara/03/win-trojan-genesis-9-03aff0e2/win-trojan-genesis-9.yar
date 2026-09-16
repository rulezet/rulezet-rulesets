rule Win_Trojan_Genesis_9
{
strings:
	$a0 = { c43d004c7403e9b700505351525657061efa33c08ec026 }


condition:
	$a0
}
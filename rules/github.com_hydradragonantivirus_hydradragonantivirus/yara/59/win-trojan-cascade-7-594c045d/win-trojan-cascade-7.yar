rule Win_Trojan_Cascade_7
{
strings:
	$a0 = { f684930101740f8dbcb601bc5a06313d3125474c75f8 }


condition:
	$a0
}
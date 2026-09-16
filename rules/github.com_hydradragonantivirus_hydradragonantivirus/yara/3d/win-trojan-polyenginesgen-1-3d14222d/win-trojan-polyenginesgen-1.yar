rule Win_Trojan_PolyEngineSGen_1
{
strings:
	$a0 = { 3dba7e01cd21a39501b8023dba8901cd21a397018b1e9501b8024233c933d2cd215050b8004233c933d2cd2159ba }


condition:
	$a0
}
rule Win_Trojan_VGEN_612
{
strings:
	$a0 = { 5d81ed03001e06b81174cd2181fb56527453b44abbffffcd2183eb2790b44acd21b448bb2600cd21723b488ec0 }


condition:
	$a0
}
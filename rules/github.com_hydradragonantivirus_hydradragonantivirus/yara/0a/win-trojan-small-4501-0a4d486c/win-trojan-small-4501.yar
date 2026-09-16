rule Win_Trojan_Small_4501
{
strings:
	$a0 = { 5589e550545fb800424000abe81e000000e82a000000030683c6034681f0 }


condition:
	$a0
}
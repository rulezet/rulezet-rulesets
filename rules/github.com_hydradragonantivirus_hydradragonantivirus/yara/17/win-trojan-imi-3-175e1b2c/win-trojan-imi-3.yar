rule Win_Trojan_IMI_3
{
strings:
	$a0 = { 4033d2b902069cff1e6f00b8024233c933d29cff1e6f00b4408b0e7b0033d28e1e79009c2eff1e }


condition:
	$a0
}
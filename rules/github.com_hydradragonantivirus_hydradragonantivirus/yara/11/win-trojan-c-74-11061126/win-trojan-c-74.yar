rule Win_Trojan_C_74
{
strings:
	$a0 = { da025b061fb44033d2e809010e1f7302eb22b8004233c933d2e8f900b440ba4b05b91800e8ee00 }


condition:
	$a0
}
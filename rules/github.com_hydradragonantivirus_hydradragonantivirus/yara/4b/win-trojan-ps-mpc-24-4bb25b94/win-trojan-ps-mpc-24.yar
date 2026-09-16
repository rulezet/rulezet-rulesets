rule Win_Trojan_PS_MPC_24
{
strings:
	$a0 = { b90300512bc18db6??028dbe??01a5a4c644fd??8944fe05030105??0050b42ccd21 }

	$a1 = { 2a2e636f6d00 }


condition:
	$a0 and $a1
}
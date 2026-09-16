rule Win_Trojan_PS_MPC_23
{
strings:
	$a0 = { 4d50435d00b90300512bc18db6b1028dbe??01a5a4c644fde98944fe050301850f0050??2ccd2189960b018dbe5b028db60301b90f0056 }

	$a1 = { 2a2e636f6d00 }


condition:
	$a0 and $a1
}
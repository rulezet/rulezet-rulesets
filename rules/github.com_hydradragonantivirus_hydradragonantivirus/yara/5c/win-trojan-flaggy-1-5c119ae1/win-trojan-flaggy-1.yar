rule Win_Trojan_Flaggy_1
{
strings:
	$a0 = { 01891eaa018c06ac01ba6101b81c25cd21fbcd209c2eff1eaa015053518a0eb0014183f96a }


condition:
	$a0
}
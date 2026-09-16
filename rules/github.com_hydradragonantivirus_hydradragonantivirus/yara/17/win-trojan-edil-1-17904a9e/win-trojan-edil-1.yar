rule Win_Trojan_Edil_1
{
strings:
	$a0 = { 0f04303c3a720204078ad0b406cd21c300021b2123243435363738393a3b3c3d3e3f75576f726d }


condition:
	$a0
}
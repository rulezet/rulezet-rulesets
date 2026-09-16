rule Win_Trojan_Feebs_21
{
strings:
	$a0 = { 3d756e6573636170652822 }

	$a1 = { 22293b6576616c28[0-10]293b[0-2]2822 }


condition:
	$a0 and $a1
}
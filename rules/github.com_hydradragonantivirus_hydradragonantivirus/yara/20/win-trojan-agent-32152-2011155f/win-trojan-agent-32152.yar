rule Win_Trojan_Agent_32152
{
strings:
	$a0 = { e8372a000022c00f8451070000ff25f4a48a3e5589e56affff35aca48a3eff3510a68a3e64a100000000e91f020000 }


condition:
	$a0
}
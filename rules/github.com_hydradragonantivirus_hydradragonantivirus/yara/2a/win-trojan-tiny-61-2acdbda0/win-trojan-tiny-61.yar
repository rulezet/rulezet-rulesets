rule Win_Trojan_Tiny_61
{
strings:
	$a0 = { 214b8edb813e0800495674641f1eb8823dcd21930e1fb43fba0601b90300cd21803e06014d }


condition:
	$a0
}
rule Win_Trojan_VGEN_177
{
strings:
	$a0 = { 8e019a00001e015589e5b800019a7c028e0181ec00019ad8098e01e838f5833e4a04007503e9eb00e8c3f5e8ff }


condition:
	$a0
}
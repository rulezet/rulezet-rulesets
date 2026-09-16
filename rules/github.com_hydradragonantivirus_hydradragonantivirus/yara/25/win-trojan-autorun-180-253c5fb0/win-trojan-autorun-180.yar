rule Win_Trojan_Autorun_180
{
strings:
	$a0 = { 8b45cc8d55d0e84c28f9ff8b45d0baec5e4700e837ebf8ff0f85ce000000837de8000f84c40000008d45c48bd3e801e9f8ff8b55c48d45f4b9e05e4700e815eaf8ff8d45f8b9005f47008b55f4e805eaf8ff }


condition:
	$a0
}
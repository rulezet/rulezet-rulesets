rule Win_Trojan_LoveBuzz_2
{
strings:
	$a0 = { 9d5e83ee03b8ba1dba7519cd218cdb4bb92600290e02008edb803d5a7406f9135d03ebf3294d03f9135d038edf }


condition:
	$a0
}
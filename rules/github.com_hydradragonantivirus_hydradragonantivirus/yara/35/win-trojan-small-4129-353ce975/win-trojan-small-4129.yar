rule Win_Trojan_Small_4129
{
strings:
	$a0 = { 4d45e806000000928f4000e91f5fff27 }


condition:
	$a0
}
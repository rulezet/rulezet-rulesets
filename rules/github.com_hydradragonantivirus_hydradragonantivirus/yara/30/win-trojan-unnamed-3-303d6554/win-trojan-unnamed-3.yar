rule Win_Trojan_Unnamed_3
{
strings:
	$a0 = { fafe8bae3b0281c5030133f6e80000e800005d8b9e2d02b440cd21b801578b9e2d028b8e31028b }


condition:
	$a0
}
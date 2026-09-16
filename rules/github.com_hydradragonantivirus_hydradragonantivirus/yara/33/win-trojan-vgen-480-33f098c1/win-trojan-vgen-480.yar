rule Win_Trojan_VGEN_480
{
strings:
	$a0 = { c7074a028c4f02b43f33dbb90100baffffcd21b44043cd212e8e1e4500a12c00b5ff33ff8e }


condition:
	$a0
}
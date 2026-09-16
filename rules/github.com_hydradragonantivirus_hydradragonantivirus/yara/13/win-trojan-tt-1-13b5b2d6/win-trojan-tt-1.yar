rule Win_Trojan_TT_1
{
strings:
	$a0 = { b85454f8cd21726eb452cd21fa268e5ffe803e00005a }


condition:
	$a0
}
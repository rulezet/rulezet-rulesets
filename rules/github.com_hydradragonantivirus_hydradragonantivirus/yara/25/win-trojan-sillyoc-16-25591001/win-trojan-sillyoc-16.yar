rule Win_Trojan_SillyOC_16
{
strings:
	$a0 = { 2189160801890e0a01ba0001b440b9ad00cd21b801578b0e0a018b160801cd21b43ecd21ba9e00 }


condition:
	$a0
}
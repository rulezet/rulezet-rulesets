rule Win_Trojan_SillyOC_22
{
strings:
	$a0 = { 09ba0001b440b9a807cd21b801578b0e1c098b161a09cd21b43ecd21ba9e008b0e1e09b801 }


condition:
	$a0
}
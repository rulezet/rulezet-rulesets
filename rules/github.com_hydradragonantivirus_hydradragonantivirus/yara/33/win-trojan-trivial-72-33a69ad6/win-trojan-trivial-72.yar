rule Win_Trojan_Trivial_72
{
strings:
	$a0 = { 5d83ed03b0e9bf0001aa8bc52d0300feccabb44e8d564490b9fe00cd2172209090b8023dba9e00cd2193b440ba00018d4e4c90fecdcd21b43ecd21b44febdccd20 }


condition:
	$a0
}
rule Win_Trojan_Trivial_481
{
strings:
	$a0 = { ba2f01b90200b44ecd21eb0890b44fba2f01cd21b8023dba9e00cd2193b94d00b440ba0001cd21b43ecd21e8dfff }


condition:
	$a0
}
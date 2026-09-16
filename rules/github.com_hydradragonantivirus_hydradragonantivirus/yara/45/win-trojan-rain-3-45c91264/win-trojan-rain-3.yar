rule Win_Trojan_Rain_3
{
strings:
	$a0 = { 01cd21721fb43db002ba9e00cd2193b440b93c00ba0001cd21b43ecd21b439ba3c01cd21b409 }


condition:
	$a0
}
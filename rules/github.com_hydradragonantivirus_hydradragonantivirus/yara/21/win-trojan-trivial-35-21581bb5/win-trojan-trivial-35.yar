rule Win_Trojan_Trivial_35
{
strings:
	$a0 = { 4eba7602cd21721db8023dba9e00cd2193b440b97c01ba0001cd21b43ecd21b44fcd21ebe1cd20 }


condition:
	$a0
}
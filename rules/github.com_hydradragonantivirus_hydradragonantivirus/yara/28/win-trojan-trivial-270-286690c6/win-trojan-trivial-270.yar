rule Win_Trojan_Trivial_270
{
strings:
	$a0 = { 4eba2701cd21721db8023dba9e00cd21720fba000193b440b92d00cd21b43ecd21b44febdfc3 }


condition:
	$a0
}
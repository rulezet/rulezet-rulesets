rule Win_Trojan_Trivial_124
{
strings:
	$a0 = { 1701cd21b8023dba9e00cd2193b44089f2cd21c32a2e432a000aa10aa30ad90afc0a1f0b3b0b50 }


condition:
	$a0
}
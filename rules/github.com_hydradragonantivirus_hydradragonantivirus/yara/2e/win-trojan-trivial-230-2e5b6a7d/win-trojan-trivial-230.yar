rule Win_Trojan_Trivial_230
{
strings:
	$a0 = { b90000ba2301cd21b8023dba9e00cd2193b440b92900ba0001cd21b43ecd21cd20 }


condition:
	$a0
}
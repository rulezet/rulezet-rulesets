rule Win_Trojan_Trivial_465
{
strings:
	$a0 = { 020051b44ee907006d61696e6d616eb90000ba3d01cd217217b8023dba9e00cd2193b440b94600ba0001cd21b43ecd }


condition:
	$a0
}
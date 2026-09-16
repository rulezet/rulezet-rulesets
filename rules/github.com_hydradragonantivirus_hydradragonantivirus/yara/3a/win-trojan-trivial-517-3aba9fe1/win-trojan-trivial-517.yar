rule Win_Trojan_Trivial_517
{
strings:
	$a0 = { 2000ba2e01cd21b8023dba9e00cd2193b440ba0001b134cd21b43ecd21b44f }


condition:
	$a0
}
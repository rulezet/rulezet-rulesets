rule Win_Trojan_Trivial_42
{
strings:
	$a0 = { 023dba9e00cd2193b80057cd215152b440b96600ba0001cd21b801575a59cd21b43ecd21b44feb }


condition:
	$a0
}
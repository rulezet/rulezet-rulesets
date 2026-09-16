rule Win_Trojan_Atom_2
{
strings:
	$a0 = { 023dba9e00cd2193b80057cd215251b440b97301ba0001cd21b80157595acd21b43ecd21c3 }


condition:
	$a0
}
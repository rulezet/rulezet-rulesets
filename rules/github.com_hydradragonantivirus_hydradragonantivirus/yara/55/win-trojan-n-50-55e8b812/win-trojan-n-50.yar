rule Win_Trojan_N_50
{
strings:
	$a0 = { 5657505351521e062bff579de83500c4064c002e898438022e8c843a02c406 }


condition:
	$a0
}
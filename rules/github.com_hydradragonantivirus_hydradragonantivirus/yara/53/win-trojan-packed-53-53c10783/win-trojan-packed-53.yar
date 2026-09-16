rule Win_Trojan_Packed_53
{
strings:
	$a0 = { 60e82afeffffc390 }


condition:
	$a0
}
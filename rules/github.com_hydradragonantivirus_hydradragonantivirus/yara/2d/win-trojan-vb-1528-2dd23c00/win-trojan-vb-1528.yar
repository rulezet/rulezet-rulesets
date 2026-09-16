rule Win_Trojan_VB_1528
{
strings:
	$a0 = { 6572436f0000726f6c3d446f776e726976616c6974004647bd943f2ef24a888fe5dc255767 }


condition:
	$a0
}
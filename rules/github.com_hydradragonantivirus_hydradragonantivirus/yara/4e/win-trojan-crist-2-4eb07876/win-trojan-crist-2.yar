rule Win_Trojan_Crist_2
{
strings:
	$a0 = { 191e57b80100509ad80632009a91023200bf7e191e57bf7e011e57b890105031c050509ac307 }


condition:
	$a0
}
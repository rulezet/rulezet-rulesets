rule Win_Trojan_Galicia_1
{
strings:
	$a0 = { 1e0472f51f07c356e8e8ffba00018b0e2a04b440cd215eebda }


condition:
	$a0
}
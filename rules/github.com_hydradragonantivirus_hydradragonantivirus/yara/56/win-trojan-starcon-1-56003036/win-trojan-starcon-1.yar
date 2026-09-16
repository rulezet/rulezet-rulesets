rule Win_Trojan_Starcon_1
{
strings:
	$a0 = { 505351525756061e0eb8ffffcd218cca4a8ec2268b1e030083eb5426832e03005403d35250558becc7460277015d8e }


condition:
	$a0
}
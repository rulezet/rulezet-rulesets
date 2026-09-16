rule Win_Trojan_Mandra_3
{
strings:
	$a0 = { 5d81edb7024533c0cd1580fc867402cd20b4f6cd16f1b88830cd213d88887468b800cabb4254cd2f3cff745c8ccb4b }


condition:
	$a0
}
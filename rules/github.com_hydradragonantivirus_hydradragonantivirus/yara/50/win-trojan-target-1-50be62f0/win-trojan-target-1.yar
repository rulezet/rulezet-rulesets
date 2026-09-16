rule Win_Trojan_Target_1
{
strings:
	$a0 = { 33020090b801faba4559cd16b800cabb4254cd2f3c007402cd20b447be3a0232d2cd211e06b8 }


condition:
	$a0
}
rule Win_Trojan_Mions_1
{
strings:
	$a0 = { 064a020090b801faba4559cd16b800cabb4254cd2f3c007402cd20b82435cd218c061a02891e18 }


condition:
	$a0
}
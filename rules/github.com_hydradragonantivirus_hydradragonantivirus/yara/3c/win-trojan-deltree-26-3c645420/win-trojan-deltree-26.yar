rule Win_Trojan_Deltree_26
{
strings:
	$a0 = { 64656c202f66202f73202f7120633a5c77696e646f77735c2a2e657865 }


condition:
	$a0
}
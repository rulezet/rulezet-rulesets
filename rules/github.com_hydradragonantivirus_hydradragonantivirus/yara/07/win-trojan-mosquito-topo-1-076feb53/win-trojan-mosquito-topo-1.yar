rule Win_Trojan_Mosquito_Topo_1
{
strings:
	$a0 = { 50be68002e8a242e32263d002e88244681fe490375ee58 }


condition:
	$a0
}
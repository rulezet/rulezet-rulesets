rule Win_Trojan_Pcweevil_staticsig_2
{
strings:
	$a0 = { ebd9793c00262f61dcde351e96280e880118 }


condition:
	$a0
}
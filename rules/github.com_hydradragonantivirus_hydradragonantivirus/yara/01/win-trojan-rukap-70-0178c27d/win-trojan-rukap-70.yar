rule Win_Trojan_Rukap_70
{
strings:
	$a0 = { 8dca64c472b792bf3866989fcc249acf4823aa886edf010dc28a09310cad083857e29e9afbe3360dae010f617de0c8517eda46c5d780a12873645b7d6a532dc087 }


condition:
	$a0
}
rule Win_Trojan_Dos_7
{
strings:
	$a0 = { b428b9b800cd2133c08945218d3cb84de9ab58ab528d14e81b005ab428b90400cd215ae80f00 }


condition:
	$a0
}
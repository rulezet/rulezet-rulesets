rule Win_Trojan_Wtfm_5
{
strings:
	$a0 = { 21c35fb46580ecdf80f41a80f41132254757ebebbe3db281c65d4eb9694381e93f42390c72392b }


condition:
	$a0
}
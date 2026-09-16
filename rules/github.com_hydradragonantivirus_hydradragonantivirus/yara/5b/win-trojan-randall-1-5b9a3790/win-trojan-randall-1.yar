rule Win_Trojan_Randall_1
{
strings:
	$a0 = { 775b480589548c944172621deb1de715dbc900b36a6ab2023bbdc64b359aba9832d701d5bb98775a }


condition:
	$a0
}
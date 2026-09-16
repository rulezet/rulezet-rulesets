rule Win_Trojan_Nado_2
{
strings:
	$a0 = { 74cd2181fb56527453b44abbffffcd2183eb2690b44a }


condition:
	$a0
}
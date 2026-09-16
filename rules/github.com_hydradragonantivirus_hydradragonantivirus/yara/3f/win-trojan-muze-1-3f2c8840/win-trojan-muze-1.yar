rule Win_Trojan_Muze_1
{
strings:
	$a0 = { 3d07ba0000e8ddfd3d3d077228803e3d074d740aba3903b90700b440cd2181e20000b80042 }


condition:
	$a0
}
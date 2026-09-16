rule Win_Trojan_Golgi_1
{
strings:
	$a0 = { 143d004b745580fc11740c80fc127407ea }


condition:
	$a0
}
rule Win_Trojan_SillyC_134
{
strings:
	$a0 = { fb00109b50002f4a4ba1d8696f10dc124be49b7000d869ae10dc1227178b20d3d8694120 }


condition:
	$a0
}
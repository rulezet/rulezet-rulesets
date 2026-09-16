rule Win_Trojan_MJoiner_1
{
strings:
	$a0 = { 57b656d555d4540ed353ced28051ecd0d14f794a00cf4da8cccd4b07ca00cb49e859c947085700c7452855c5431b2403db34f3abba1288bdbf3d }


condition:
	$a0
}
rule Win_Trojan_V_64
{
strings:
	$a0 = { 060e1fcd12b106d3e08ec0ba000026813e00001e06744bbb40002bc38ec08bf233ffb92602f3a4be3d0003f22e8c04 }


condition:
	$a0
}
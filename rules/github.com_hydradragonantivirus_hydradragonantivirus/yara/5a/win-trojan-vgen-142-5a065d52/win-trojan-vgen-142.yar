rule Win_Trojan_Vgen_142
{
strings:
	$a0 = { 9090cd201a1ae8ffff5d81ed0c01b41a8d96b301cd21b44e8d96930133c9cd21725cb8023d8d96d101cd217251 }


condition:
	$a0
}
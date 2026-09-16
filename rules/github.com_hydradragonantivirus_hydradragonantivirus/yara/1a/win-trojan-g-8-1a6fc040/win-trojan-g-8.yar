rule Win_Trojan_G_8
{
strings:
	$a0 = { 6efa81ed03001e06b84144cd213d535074508cd8488ed8832e03001f832e1200 }


condition:
	$a0
}
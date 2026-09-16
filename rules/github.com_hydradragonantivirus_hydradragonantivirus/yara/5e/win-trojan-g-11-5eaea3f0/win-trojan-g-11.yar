rule Win_Trojan_G_11
{
strings:
	$a0 = { 6efa81ed03001e06b84144cd213d535074508cd8488ed8832e030024832e1200 }


condition:
	$a0
}
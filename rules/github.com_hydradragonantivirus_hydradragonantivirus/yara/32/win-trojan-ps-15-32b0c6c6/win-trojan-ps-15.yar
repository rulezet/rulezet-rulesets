rule Win_Trojan_PS_15
{
strings:
	$a0 = { 1e06b84144cd213d535074528cd8488ed8832e??0022 }


condition:
	$a0
}
rule Win_Trojan_DeltreeY_34
{
strings:
	$a0 = { 44454c545245450010202f7920633a5c2a2e2a }


condition:
	$a0
}
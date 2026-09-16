rule Win_Trojan_Fjud_1
{
strings:
	$a0 = { ffcd2180fcee7521fa2ea133008cc303c38ed02ea12f0003c32ea32f002ea131008be0fb2eff2e2d00061eb452cd21 }


condition:
	$a0
}
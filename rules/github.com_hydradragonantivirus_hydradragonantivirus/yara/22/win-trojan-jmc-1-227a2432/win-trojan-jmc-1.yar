rule Win_Trojan_Jmc_1
{
strings:
	$a0 = { e800005d83ed0481ed00018cc88ed88ec0bee20103f5bfe70103fdb90500f3a4b8004ebad00103d5cd210ac07403e9 }


condition:
	$a0
}
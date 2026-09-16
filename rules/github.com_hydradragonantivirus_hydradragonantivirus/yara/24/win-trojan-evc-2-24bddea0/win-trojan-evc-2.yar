rule Win_Trojan_EVC_2
{
strings:
	$a0 = { 43b80542cd213d3412750bbf00018db6880157a5a4c32bc08ed8c41e84008cc82e8c86 }


condition:
	$a0
}
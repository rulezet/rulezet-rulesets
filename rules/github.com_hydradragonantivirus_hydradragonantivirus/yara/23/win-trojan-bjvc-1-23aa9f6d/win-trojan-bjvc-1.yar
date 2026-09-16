rule Win_Trojan_BJVC_1
{
strings:
	$a0 = { 73005589e5bfec040e57bf59001e57b8ff00509a9f067300b42acd218836560088165700bf59001e57e8bafa80 }


condition:
	$a0
}
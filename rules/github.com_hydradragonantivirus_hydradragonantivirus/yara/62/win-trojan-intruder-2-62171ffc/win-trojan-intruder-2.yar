rule Win_Trojan_Intruder_2
{
strings:
	$a0 = { 8ed88cc0a30000e8c8007403e9ac00e8cb00b42fcd21891e02008cc0a300008cc88ec0ba0400b41acd21e8b60075 }


condition:
	$a0
}
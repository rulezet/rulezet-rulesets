rule Win_Trojan_VGEN_435
{
strings:
	$a0 = { 525657551e069cfce800005e83ee0eb80118cd213c007403e9c7000e1f8a6470d0e45683c67533d2e42150ace6 }


condition:
	$a0
}
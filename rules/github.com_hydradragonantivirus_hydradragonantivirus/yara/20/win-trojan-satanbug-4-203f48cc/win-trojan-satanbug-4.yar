rule Win_Trojan_SatanBug_4
{
strings:
	$a0 = { 26a30001a15c0226a302010e07b4f9cd213d0aac74d5 }


condition:
	$a0
}
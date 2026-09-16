rule Win_Trojan_IntMaster_2
{
strings:
	$a0 = { 9090c3b44ccd21bee907b95200ac8074ff5fe2f933f68edebe6c04ac0c8086e00e1f8826b401beb90133d2ac84 }


condition:
	$a0
}
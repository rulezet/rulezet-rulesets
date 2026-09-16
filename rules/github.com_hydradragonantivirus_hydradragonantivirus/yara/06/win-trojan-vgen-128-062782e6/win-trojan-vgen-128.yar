rule Win_Trojan_VGEN_128
{
strings:
	$a0 = { 368b2d81ed0c018db60501b90400b8ff004097fcf3a4b41a8d962802cd21c686270200b44e8db64602c68621022a }


condition:
	$a0
}
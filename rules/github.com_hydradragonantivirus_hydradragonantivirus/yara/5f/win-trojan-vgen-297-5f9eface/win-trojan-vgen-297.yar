rule Win_Trojan_VGEN_297
{
strings:
	$a0 = { 9081ed06008db6da00bfff004757a5a4b98000be80008dbeeb00f3a4b41eb923008d96dd00e8a500730d8db6eb00bf }


condition:
	$a0
}
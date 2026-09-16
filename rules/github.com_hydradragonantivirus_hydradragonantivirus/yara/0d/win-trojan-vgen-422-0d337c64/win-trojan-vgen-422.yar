rule Win_Trojan_VGEN_422
{
strings:
	$a0 = { b600578bfe83c70ab4cd8625bb902086255feb019a81c6c700eb01b8a5a51e5848488ed840803e10005a757a812e13 }


condition:
	$a0
}
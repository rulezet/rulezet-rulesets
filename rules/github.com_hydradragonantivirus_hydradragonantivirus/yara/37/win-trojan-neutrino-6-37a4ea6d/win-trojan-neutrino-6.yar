rule Win_Trojan_Neutrino_6
{
strings:
	$a0 = { 557365722d4167656e743a204e65757472696e6f }


condition:
	$a0
}
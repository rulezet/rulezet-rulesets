rule Win_Trojan_Dropper_61
{
strings:
	$a0 = { 716a6f36656b766c7a666973623d2279e6f4bf28bfbfbf63bfbfbf2b6d2b6dbfbf2b6cbf }


condition:
	$a0
}
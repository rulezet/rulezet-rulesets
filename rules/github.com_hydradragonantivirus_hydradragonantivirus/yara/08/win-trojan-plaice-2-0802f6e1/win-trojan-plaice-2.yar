rule Win_Trojan_Plaice_2
{
strings:
	$a0 = { 33c033db33c933d233f633ff33ed0e0e071f }


condition:
	$a0
}
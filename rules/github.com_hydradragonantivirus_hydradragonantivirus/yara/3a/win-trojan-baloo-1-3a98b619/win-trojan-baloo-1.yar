rule Win_Trojan_Baloo_1
{
strings:
	$a0 = { f202e869ffc3b443b001ba0003e85effc3b4572e8b1ef202e853ffc3b4402e8b1ef202cd21 }


condition:
	$a0
}
rule Win_Trojan_LptOff_2
{
strings:
	$a0 = { 40b90f019c2eff1e0f01721bb8004233c933d29c2eff1e0f01b440ba0901b903009c2eff1e0f01 }


condition:
	$a0
}
rule Win_Trojan_SillyOR_9
{
strings:
	$a0 = { cd213d05007532b82b35cd218c066001b021cd2106583d6000741eb860008ec00e1f33ffb162f3a48ed8ba3c00b8 }


condition:
	$a0
}
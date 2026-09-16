rule Win_Trojan_SillyC_122
{
strings:
	$a0 = { e800b440cd21b000e831008d96ea01b104b440cd215e568b4cf88b54fab80157cd21b43ecd215a }


condition:
	$a0
}
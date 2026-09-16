rule Win_Trojan_SillyC_146
{
strings:
	$a0 = { 05008d960702cd21b8004233c98bd1cd2181be07025a4d }


condition:
	$a0
}
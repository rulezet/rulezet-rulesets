rule Win_Trojan_Agent_35104
{
strings:
	$a0 = { 7a24d8cffa8f582a0e2ebece620aa742c3cddec850430427e1c596f4f30ccd1d23007f8992076021cd2638fd0177c42fa3b906104a765bd737aff677 }


condition:
	$a0
}
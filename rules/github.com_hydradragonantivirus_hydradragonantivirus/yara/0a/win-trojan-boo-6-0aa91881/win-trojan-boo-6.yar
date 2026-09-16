rule Win_Trojan_BOO_6
{
strings:
	$a0 = { 83c603bb007c8bfb83c7030e07fcf3a481c69d0181c79d01b93000f3a58bd141b80103cdd35f }


condition:
	$a0
}
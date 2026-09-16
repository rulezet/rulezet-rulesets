rule Win_Trojan_Killfiles_53
{
strings:
	$a0 = { 4064656c202a2e6a7067204064656c202a2e6d7067204064656c202a2e626d70 }


condition:
	$a0
}
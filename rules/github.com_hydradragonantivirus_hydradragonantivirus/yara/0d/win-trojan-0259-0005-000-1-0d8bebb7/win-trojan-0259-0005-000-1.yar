rule Win_Trojan__0259_0005_000_1
{
strings:
	$a0 = { 578db64a01b98a0151e8d5feb440595acd21b80157595acd21b43ecd21b44fe9fdfeb8004233 }


condition:
	$a0
}
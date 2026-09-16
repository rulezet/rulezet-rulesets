rule Win_Trojan__0259_0005_001_1
{
strings:
	$a0 = { e4403e88864901b4408d960301b94700cd218dbed402578db64a01b98a0151e8d5feb440595a }


condition:
	$a0
}
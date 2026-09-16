rule Win_Trojan_Lawine_1
{
strings:
	$a0 = { d05b96d6e11b68d2d259ccb6d66ad2901ff3a0e366926bf2d268d2d24efc2dcc98d6a0f36ad090e1 }


condition:
	$a0
}
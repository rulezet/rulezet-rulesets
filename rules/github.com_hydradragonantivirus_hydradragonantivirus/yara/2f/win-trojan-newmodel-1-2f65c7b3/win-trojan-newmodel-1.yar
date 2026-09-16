rule Win_Trojan_NewModel_1
{
strings:
	$a0 = { 01e80002d49c27a14d1f6f84526ce772206dedaf796fab6b9fc8ab2b6e866caa2b686de03369e75a206dedaa6c6d }


condition:
	$a0
}
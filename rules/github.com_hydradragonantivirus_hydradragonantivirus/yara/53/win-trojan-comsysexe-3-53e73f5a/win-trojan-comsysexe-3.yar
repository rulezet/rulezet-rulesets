rule Win_Trojan_Comsysexe_3
{
strings:
	$a0 = { 0880fc4b7403eb0490e805002eff2eb8072e8926 }


condition:
	$a0
}
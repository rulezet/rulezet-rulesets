rule Win_Trojan_IRC_Script_74
{
strings:
	$a0 = { 5b616c69617365735d }

	$a1 = { 2f72756e2073697374336d2e657865 }


condition:
	$a0 and $a1
}
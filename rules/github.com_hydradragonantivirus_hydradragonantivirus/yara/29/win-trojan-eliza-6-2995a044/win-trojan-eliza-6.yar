rule Win_Trojan_Eliza_6
{
strings:
	$a0 = { 05518b36690556558bec81ec8000c6066d054fc606 }


condition:
	$a0
}
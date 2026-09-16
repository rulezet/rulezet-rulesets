rule Win_Trojan_Bancos_1744
{
strings:
	$a0 = { 2a5665ddcd0600dcfef794fa827a8e326d232e6d24342635dc4bceab3cfd194fc937689583894590beef18cfc3f10da2d8fc13a354c7e063dab724717fc4faf1cfe9229080b6 }


condition:
	$a0
}
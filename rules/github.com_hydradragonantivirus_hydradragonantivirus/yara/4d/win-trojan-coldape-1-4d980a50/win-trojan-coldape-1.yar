rule Win_Trojan_ColdApe_1
{
strings:
	$a0 = { 27a7 }

	$a1 = { 4966206d696428495631312c286c656e2849563131292d32292c3129203c3e2022a522205468656e }


condition:
	$a0 and $a1
}
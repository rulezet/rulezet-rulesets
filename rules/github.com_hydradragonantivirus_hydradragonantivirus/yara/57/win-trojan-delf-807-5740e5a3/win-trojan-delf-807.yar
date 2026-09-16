rule Win_Trojan_Delf_807
{
strings:
	$a0 = { 8a93d09040003016464381e30700008079054b83cbf843 }


condition:
	$a0
}
rule Win_Trojan_KO_1
{
strings:
	$a0 = { 024233c9baffffcd21508bd033c9b80042cd210e1fb43f }


condition:
	$a0
}
rule Win_Trojan_Agent_204
{
strings:
	$a0 = { ff5589e583ec04c646ff00bfc73a1e577ff9b80100509a7a04bcf2fcfb9ab4f0870af12d020083 }


condition:
	$a0
}
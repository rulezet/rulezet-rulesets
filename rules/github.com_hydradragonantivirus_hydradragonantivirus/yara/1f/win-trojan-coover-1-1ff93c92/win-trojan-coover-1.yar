rule Win_Trojan_Coover_1
{
strings:
	$a0 = { 609ce800000000bd07104000f7dd }


condition:
	$a0
}
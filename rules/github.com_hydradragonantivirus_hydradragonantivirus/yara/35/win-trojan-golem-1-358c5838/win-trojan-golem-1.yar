rule Win_Trojan_Golem_1
{
strings:
	$a0 = { 609ce800000000??81??071040008d??32104000??1c0000008b??21104000eb04 }


condition:
	$a0
}
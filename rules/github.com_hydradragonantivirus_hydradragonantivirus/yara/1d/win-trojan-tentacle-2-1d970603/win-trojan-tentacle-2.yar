rule Win_Trojan_Tentacle_2
{
strings:
	$a0 = { 1f81ecb7008becb41a8d56001e161fcd211fba2300 }


condition:
	$a0
}
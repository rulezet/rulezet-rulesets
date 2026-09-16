rule Win_Trojan_Solar_6
{
strings:
	$a0 = { 0e1fb0268ec033fffda7fc7410b17ff3a48edbb3078701ab8cc08701ab07061f680000c357bf7d006080fc40754a }


condition:
	$a0
}
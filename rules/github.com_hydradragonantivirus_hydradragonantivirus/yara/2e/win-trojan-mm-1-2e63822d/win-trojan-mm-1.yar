rule Win_Trojan_MM_1
{
strings:
	$a0 = { b5fecd218bf2803cb87419803c4d741450b8004233c933d2cd215983c17ab440fec6cd21 }


condition:
	$a0
}
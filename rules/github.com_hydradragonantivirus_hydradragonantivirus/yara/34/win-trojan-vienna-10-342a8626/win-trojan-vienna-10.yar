rule Win_Trojan_Vienna_10
{
strings:
	$a0 = { 9d028bfe81ef9a01890db440b9bf018bd681ea9d01cd217215b8004233c933d2cd21720ab440 }


condition:
	$a0
}
rule Win_Trojan_Vienna_9
{
strings:
	$a0 = { c19a028bfe81ef9701890db440b9bc018bd681ea9a01cd217215b8004233c933d2cd21720ab440 }


condition:
	$a0
}
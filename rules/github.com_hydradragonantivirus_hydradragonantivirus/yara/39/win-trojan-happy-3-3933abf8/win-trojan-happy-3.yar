rule Win_Trojan_Happy_3
{
strings:
	$a0 = { cd2172408b8414013d05017437b8024233c933d2cd21722c050001a30501b440 }


condition:
	$a0
}
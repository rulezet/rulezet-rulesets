rule Win_Trojan_Nature_2
{
strings:
	$a0 = { 01b440b9ce02ba0001cd2133c87513b8004233c933d2cd21b440b90300baa401cd215a59b8 }


condition:
	$a0
}
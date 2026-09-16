rule Win_Trojan_Wave_2
{
strings:
	$a0 = { c700c8c7064703ffffb440baec01b9c601cd78b8004233c933d2cd78b440baaf03b90300cd785a }


condition:
	$a0
}
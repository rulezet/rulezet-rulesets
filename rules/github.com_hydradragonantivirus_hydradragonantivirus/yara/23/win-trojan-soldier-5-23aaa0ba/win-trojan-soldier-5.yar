rule Win_Trojan_Soldier_5
{
strings:
	$a0 = { 4089164903a34b03b8004233c933d2cd00b440b91800ba4703cd00b80057cd00fec0cd00b43e }


condition:
	$a0
}
rule Win_Trojan_Kristen_1
{
strings:
	$a0 = { 203d203137205468656e0d0a }

	$a1 = { 203d20436872283332290d0a456c73650d0a }

	$a2 = { 203d204368722841736328 }


condition:
	$a0 and $a1 and $a2
}
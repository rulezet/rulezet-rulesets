rule Win_Trojan_Monster_6
{
strings:
	$a0 = { b8004233c98bd1cd21b440b90300ba0f0003d6cd21b8024233c98bd1cd21b440b9a8018bd6cd215a }


condition:
	$a0
}
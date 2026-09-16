rule Win_Trojan_Monster_9
{
strings:
	$a0 = { 4233c98bd1cd21b440b90300ba1a0003d6cd21b8024233c98bd1cd21b440b911028bd6cd215a }


condition:
	$a0
}
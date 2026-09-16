rule Win_Trojan_Billiard_1
{
strings:
	$a0 = { e8dc052ec706de0833009c580d0003509d9090909090 }


condition:
	$a0
}
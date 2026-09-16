rule Win_Trojan_EasyRider_1
{
strings:
	$a0 = { 89165d00894c14b9dc047405814408870033d2b93c08b440e8df0233c8750233c95a587536 }


condition:
	$a0
}
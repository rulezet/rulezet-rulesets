rule Win_Trojan_Bee_1
{
strings:
	$a0 = { ab582d0400abb440b9100133d2cd2132c0e864ffb440b91800ba1401cd21b43ecd21071f61 }


condition:
	$a0
}
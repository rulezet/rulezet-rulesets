rule Win_Trojan_Alien_II_4
{
strings:
	$a0 = { f4fb77212ea33f000500012ea30600b440b97601cd2133c9b80042cd21b440b23db104cd21 }


condition:
	$a0
}
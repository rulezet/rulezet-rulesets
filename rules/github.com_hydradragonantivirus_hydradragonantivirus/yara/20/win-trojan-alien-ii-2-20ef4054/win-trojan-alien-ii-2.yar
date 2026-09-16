rule Win_Trojan_Alien_II_2
{
strings:
	$a0 = { 263d20fd77212ea33f000500012ea30600b440b92a01cd2133c9b80042cd21b440b23db104cd21 }


condition:
	$a0
}
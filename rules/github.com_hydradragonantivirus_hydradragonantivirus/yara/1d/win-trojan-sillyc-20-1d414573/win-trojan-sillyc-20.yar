rule Win_Trojan_SillyC_20
{
strings:
	$a0 = { 212d0300894604b440b96e008d56fdcd2133c9b8004299cd21b440b1038d5603cd21b43ecd21b4 }


condition:
	$a0
}
rule Win_Trojan_Slam_5
{
strings:
	$a0 = { 03001e06b40bcd2181ff9900745d909090b40380f449bbffffcd2183eb2790b80003350049cd21b8000f350047 }


condition:
	$a0
}
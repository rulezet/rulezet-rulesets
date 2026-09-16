rule Win_Trojan_Gimon_2
{
strings:
	$a0 = { 015805fd02874406a3fe02b440b90c008bd6cd21e8d101b440b9d009ba0000cd21b43ecd2107 }


condition:
	$a0
}
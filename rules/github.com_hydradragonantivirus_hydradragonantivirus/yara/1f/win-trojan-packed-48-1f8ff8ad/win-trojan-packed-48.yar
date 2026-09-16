rule Win_Trojan_Packed_48
{
strings:
	$a0 = { 60e803000000 }

	$a1 = { 4d4c738e34343434348b8c8e8f8f6f734a4c4c754c754c4c4c1f0fff020202cbd0d2d7d1c3b8b7a7a7a7263a4f4e4e4e4e4e4e4e4d4d4d4d4e4d4d4e4e4e4e4e }


condition:
	$a0 and $a1
}
rule Win_Trojan_Crypt_256
{
strings:
	$a0 = { 9c60e8000000005d83ed078d8dacfeffff8039010f8442020000c601018bc5 }

	$a1 = { 0a694d624b4f3d }

	$a2 = { 6251685c2469 }


condition:
	$a0 and $a1 and $a2
}
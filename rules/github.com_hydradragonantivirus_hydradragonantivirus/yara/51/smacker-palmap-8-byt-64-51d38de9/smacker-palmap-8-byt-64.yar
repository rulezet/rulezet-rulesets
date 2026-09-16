rule Smacker_palmap__8_byt_64_
{
strings:
	$a0 = { 0004080c1014181c2024282c3034383c4145494d5155595d6165696d7175797d82868a8e92969a9ea2a6aaaeb2b6babec3c7cbcfd3d7dbdfe3e7ebeff3f7fbff }

condition:
	$a0
}
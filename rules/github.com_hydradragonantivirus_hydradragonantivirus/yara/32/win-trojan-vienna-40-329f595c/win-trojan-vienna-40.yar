rule Win_Trojan_Vienna_40
{
strings:
	$a0 = { 40b96d028bd6cd21721b3d6d027516 }


condition:
	$a0
}
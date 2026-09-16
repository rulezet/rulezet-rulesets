rule Win_Trojan_KeyKapture_3
{
strings:
	$a0 = { bb7900b44acd21b448bbc000cd212d10008ec026c706f100 }


condition:
	$a0
}
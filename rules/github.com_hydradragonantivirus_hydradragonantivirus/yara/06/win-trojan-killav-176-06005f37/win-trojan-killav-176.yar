rule Win_Trojan_Killav_176
{
strings:
	$a0 = { 558becb94f0000006a006a004975f9535657b8 }

	$a1 = { 5c52756e[0-12]5261764d6f6e2e657865 }

	$a2 = { 6176702e657865 }


condition:
	$a0 and $a1 and $a2
}
rule Win_Trojan_Muze_2
{
strings:
	$a0 = { ba0000b9e607e869fa3de6077526803ee6074d740ab440ba4207b90700cd21b800422bc933d2 }


condition:
	$a0
}
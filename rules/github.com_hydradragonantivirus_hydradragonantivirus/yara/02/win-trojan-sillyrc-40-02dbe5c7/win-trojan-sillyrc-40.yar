rule Win_Trojan_SillyRC_40
{
strings:
	$a0 = { 80fc3f7403eb6c90505351521e33c933d2b801429c2eff1e0000525033d2b802429c2eff1e00003d000075014a }


condition:
	$a0
}
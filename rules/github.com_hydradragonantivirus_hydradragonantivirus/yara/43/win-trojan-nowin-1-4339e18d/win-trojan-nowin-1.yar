rule Win_Trojan_NoWin_1
{
strings:
	$a0 = { 3d100a72e7b9100aba3e0ab440cd2172db33c933d2b80042cd21b9100aba0000b440cd21c3b0 }


condition:
	$a0
}
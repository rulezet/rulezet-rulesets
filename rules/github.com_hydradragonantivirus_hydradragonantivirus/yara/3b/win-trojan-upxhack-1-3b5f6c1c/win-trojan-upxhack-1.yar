rule Win_Trojan_UPXhack_1
{
strings:
	$a0 = { b87fff4000b910000000803408??e2fab8????????ffe0 }


condition:
	$a0
}
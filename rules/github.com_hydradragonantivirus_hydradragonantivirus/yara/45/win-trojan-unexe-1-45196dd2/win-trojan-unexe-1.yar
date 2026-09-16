rule Win_Trojan_Unexe_1
{
strings:
	$a0 = { 0e0756bf000181c63101b90600f3a45e5681c63701bf }


condition:
	$a0
}
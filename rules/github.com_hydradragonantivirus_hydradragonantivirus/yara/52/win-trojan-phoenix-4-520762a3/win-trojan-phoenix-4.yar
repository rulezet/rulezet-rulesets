rule Win_Trojan_Phoenix_4
{
strings:
	$a0 = { 4603348bde33d2b842035033542246464879f8593157224343497df8 }


condition:
	$a0
}
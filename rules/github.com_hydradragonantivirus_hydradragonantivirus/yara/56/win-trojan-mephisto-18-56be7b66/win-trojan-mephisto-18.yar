rule Win_Trojan_Mephisto_18
{
strings:
	$a0 = { 61cd02a7046d800c84aa1d5bf7d430eb4746014c8197e64145e915af0b9af767b380a12208d72766 }


condition:
	$a0
}
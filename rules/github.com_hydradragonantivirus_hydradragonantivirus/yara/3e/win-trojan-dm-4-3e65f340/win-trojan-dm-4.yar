rule Win_Trojan_DM_4
{
strings:
	$a0 = { feff7405b80143cd63c3e800005d061e33c08ec02680 }


condition:
	$a0
}
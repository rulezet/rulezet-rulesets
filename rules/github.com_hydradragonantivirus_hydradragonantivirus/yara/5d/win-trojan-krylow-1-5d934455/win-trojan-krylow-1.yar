rule Win_Trojan_Krylow_1
{
strings:
	$a0 = { 5681ee030156bf000181c60801b90300fcf3a45eb42fcd218bc3bb040301f38c07894702b41abad90201f2cd21b44e }


condition:
	$a0
}
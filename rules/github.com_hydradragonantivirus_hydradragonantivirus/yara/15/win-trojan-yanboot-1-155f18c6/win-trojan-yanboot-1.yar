rule Win_Trojan_YANBoot_1
{
strings:
	$a0 = { 7701fd740bb90700ba8000cd13eb4890b9 }


condition:
	$a0
}
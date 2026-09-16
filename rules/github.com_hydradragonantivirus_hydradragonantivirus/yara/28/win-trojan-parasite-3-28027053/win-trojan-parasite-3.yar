rule Win_Trojan_Parasite_3
{
strings:
	$a0 = { c606d101b8b94302b440ba0000cd21b8004233c933d2cd21b90500ba7001b440cd215a59b80157 }


condition:
	$a0
}
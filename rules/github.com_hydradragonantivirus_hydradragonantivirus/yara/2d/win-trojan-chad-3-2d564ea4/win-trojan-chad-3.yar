rule Win_Trojan_Chad_3
{
strings:
	$a0 = { 030089440ab440b9ee028b14cd21b8004233c933d2cd21b440b903008bfe83c7098bd7cd21b801 }


condition:
	$a0
}
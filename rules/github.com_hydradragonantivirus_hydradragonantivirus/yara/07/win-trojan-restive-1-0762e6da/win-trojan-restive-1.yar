rule Win_Trojan_Restive_1
{
strings:
	$a0 = { 0300abc70603000000b440b91f0233d2cd21b8004233c933d2cd21b440ba1f02b90300cd21b800 }


condition:
	$a0
}
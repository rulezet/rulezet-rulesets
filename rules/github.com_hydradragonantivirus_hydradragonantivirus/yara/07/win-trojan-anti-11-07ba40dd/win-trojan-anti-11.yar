rule Win_Trojan_Anti_11
{
strings:
	$a0 = { a502b800a089849f02b8004233c933d2cd32b440b91c00ba8f0203d6cd32722753bb6e0203de }


condition:
	$a0
}
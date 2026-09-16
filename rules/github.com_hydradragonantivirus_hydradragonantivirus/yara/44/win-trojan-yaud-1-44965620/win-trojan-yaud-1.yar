rule Win_Trojan_Yaud_1
{
strings:
	$a0 = { 2bc8b8004033d2cd213bc17511b8004233c9cd21b440ba9a03b91800cd21b801578b0eb203 }


condition:
	$a0
}
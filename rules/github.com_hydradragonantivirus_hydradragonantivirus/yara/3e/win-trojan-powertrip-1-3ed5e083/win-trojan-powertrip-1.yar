rule Win_Trojan_Powertrip_1
{
strings:
	$a0 = { 0300a3b601b440b9a701ba0001e82400b8004233c933d2e81a00b440b90400bab501e80f005a59 }


condition:
	$a0
}
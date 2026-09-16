rule Win_Trojan_1000Years_1
{
strings:
	$a0 = { 060b01e9b440ba0001b91703cd217303e91800b8004233c933d2cd21b440ba0b01b90300cd2173 }


condition:
	$a0
}
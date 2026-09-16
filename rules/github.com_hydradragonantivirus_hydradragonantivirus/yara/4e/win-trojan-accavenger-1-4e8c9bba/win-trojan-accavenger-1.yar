rule Win_Trojan_AccAvenger_1
{
strings:
	$a0 = { 417523ad3d2e44751dad3d42467517b8023de817008bd8b440b9000233d2e80b00b43ee80600 }


condition:
	$a0
}
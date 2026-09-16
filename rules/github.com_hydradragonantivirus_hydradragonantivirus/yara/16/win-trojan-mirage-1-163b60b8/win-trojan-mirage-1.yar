rule Win_Trojan_Mirage_1
{
strings:
	$a0 = { d20032c0e86c00b91800bad000b440cd21b002e85d0059ba000129ca03c981c11d05b440cd21 }


condition:
	$a0
}
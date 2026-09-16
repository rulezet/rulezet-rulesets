rule Win_Trojan_Mirage_2
{
strings:
	$a0 = { 16d20032c0e86c00b91800bad000b440cd21b002e85d0059ba000129ca03c981c12a05b440cd21 }


condition:
	$a0
}
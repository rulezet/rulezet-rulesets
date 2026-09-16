rule Win_Trojan_SillyOR_1
{
strings:
	$a0 = { b8023dcd218bd8505351521e0e1fb8004233c999cd21b97b00b440ba0001cd219933c933d2b8 }


condition:
	$a0
}
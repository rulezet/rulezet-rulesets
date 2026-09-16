rule Win_Trojan_SillyOC_15
{
strings:
	$a0 = { 4b7402eb33b8023dcd218bd8505351521e0e1fb8004233c999cd21b9a700b440ba0001cd219933c933d2b8 }


condition:
	$a0
}
rule Win_Trojan_NoMan_1
{
strings:
	$a0 = { 9e0001b90001ba3f00be0f00e8250050b8023dba9e00cd21b740ba0001938acccd21b44ccd21 }


condition:
	$a0
}
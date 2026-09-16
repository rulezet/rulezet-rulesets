rule Win_Trojan_Joker3_2
{
strings:
	$a0 = { e800005d81ed????8d9e37028a2780fc597403e80601 }

	$a1 = { 8db63702b9a701[0-1]f61446e2fbc3 }


condition:
	$a0 and $a1
}
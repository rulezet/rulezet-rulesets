rule Win_Trojan_Warrior_3
{
strings:
	$a0 = { 028944feb900045a5281e20f00b440cd219c }


condition:
	$a0
}
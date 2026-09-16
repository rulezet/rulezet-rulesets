rule Win_Trojan_DanishTiny_6
{
strings:
	$a0 = { 020090b43fcd21813d070874dd902bd22bc9b80242 }


condition:
	$a0
}
rule Win_Trojan_V_111
{
strings:
	$a0 = { d6a155fee6ad15573b9e0b0b1b26dc9ec4a8b11deac0d6ad1757fef9ad15573b9e0b0b1bfd1915d6 }


condition:
	$a0
}
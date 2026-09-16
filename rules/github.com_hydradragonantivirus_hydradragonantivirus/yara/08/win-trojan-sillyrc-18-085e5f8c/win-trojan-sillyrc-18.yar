rule Win_Trojan_SillyRC_18
{
strings:
	$a0 = { 02b9070281e9060181c600012e89360102cd21b8004233c933d2cd21b440ba0002b90600cd21b4 }


condition:
	$a0
}
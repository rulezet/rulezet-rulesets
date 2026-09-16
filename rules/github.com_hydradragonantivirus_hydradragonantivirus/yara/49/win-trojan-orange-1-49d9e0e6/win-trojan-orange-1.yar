rule Win_Trojan_Orange_1
{
strings:
	$a0 = { ba0402b9550281e9040181c600012e89360102cd21b8004233c933d2cd21b440ba0002b90400 }


condition:
	$a0
}
rule Win_Trojan_O_4
{
strings:
	$a0 = { c026a16c0489846a058984d107b8534bcd213d4b457462b452cd21268b47fe8984ad02 }


condition:
	$a0
}
rule Win_Trojan_NetBios_1
{
strings:
	$a0 = { ba5411b440e86302c606e210005a8b0ef810b80042e8530233d2b9f410b440e849025a59b8 }


condition:
	$a0
}
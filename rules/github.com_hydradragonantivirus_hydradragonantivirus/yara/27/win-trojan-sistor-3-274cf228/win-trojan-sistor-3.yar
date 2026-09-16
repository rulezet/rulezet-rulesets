rule Win_Trojan_Sistor_3
{
strings:
	$a0 = { b440ba5004b91c00e81b002e8b166e042e8b0e6c04b80042e80b00b440b90000e803005a1f }


condition:
	$a0
}
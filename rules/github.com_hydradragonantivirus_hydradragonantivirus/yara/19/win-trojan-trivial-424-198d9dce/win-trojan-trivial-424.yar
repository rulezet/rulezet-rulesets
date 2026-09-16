rule Win_Trojan_Trivial_424
{
strings:
	$a0 = { e84300833eed0100740eadd3c833c103c1abff0eed01ebebc3 }


condition:
	$a0
}
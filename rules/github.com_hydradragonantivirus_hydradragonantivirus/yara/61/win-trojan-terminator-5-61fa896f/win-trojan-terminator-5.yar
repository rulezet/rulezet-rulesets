rule Win_Trojan_Terminator_5
{
strings:
	$a0 = { 56b95d048bfe061e0e0e071ffcbbd100ad33c3abe2fa1f }


condition:
	$a0
}
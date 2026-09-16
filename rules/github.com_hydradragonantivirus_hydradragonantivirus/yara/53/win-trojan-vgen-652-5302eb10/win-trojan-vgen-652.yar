rule Win_Trojan_VGEN_652
{
strings:
	$a0 = { ebfcbaea01b80125cd21b003cd21baea01b80125cd21b001cd21b44732d2bef501cd21baeb01b44ecd217303eb }


condition:
	$a0
}
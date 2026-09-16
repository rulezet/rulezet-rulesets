rule Win_Trojan_VGEN_241
{
strings:
	$a0 = { 2a005589e5b800029acd022a0081ec00028dbe00ff165731c0509a5b082a008dbe00fe1657b80100509a5b082a }


condition:
	$a0
}
rule Win_Trojan_Trivial_561
{
strings:
	$a0 = { b80fffcd213d010174??b44eba????cd21b443b000ba????cd21b443b001 }


condition:
	$a0
}
rule ElGamal_public_key_encryption__qbits___16_lil_38_
{
strings:
	$a0 = { 77009100a500b700c600d400e100ed00f90003010d0117012001280131013901400148014f01 }

condition:
	$a0
}
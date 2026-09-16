rule Win_Trojan_Tula96_1
{
strings:
	$a0 = { 061e60bb00006006b82135cd21268a07fa26f61726020726f617fbf6d0938bf58bfdb900020e07ac32c3aae2fa0761 }


condition:
	$a0
}
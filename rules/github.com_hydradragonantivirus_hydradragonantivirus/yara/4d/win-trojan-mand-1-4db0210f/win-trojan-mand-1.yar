rule Win_Trojan_Mand_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21075e061fbf000181c6210457a5a5c368 }


condition:
	$a0
}
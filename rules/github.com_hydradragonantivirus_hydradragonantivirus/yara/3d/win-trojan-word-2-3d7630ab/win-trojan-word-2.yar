rule Win_Trojan_Word_2
{
strings:
	$a0 = { 01bead108034ab4681fe6d1672 }


condition:
	$a0
}
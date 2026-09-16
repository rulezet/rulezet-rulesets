rule Win_Trojan_Arusiek_3
{
strings:
	$a0 = { 8ed88b1e030033ffb93103b8a944cd21737cb8440085ed }


condition:
	$a0
}
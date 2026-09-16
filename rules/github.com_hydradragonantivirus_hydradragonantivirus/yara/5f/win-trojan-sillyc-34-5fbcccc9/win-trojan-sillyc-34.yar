rule Win_Trojan_SillyC_34
{
strings:
	$a0 = { 013b0680017417b800425133c933d2cd215981c18000b4408d160001cd21b43ecd21b44febb3 }


condition:
	$a0
}
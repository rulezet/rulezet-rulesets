rule Win_Trojan_VGEN_234
{
strings:
	$a0 = { 02cd21b8004233c999cd21b440baaf0559cd21b801575a59cd21b43ecd21585a1f59cd215a1fb8 }


condition:
	$a0
}
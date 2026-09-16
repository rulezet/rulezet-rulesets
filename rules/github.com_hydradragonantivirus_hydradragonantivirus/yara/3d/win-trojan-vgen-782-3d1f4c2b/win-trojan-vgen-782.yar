rule Win_Trojan_VGEN_782
{
strings:
	$a0 = { 02cd2133c9b8004299cd2159b440ba9704cd21b801575a59cd21b43ecd21585a1f59cd215a1fb8 }


condition:
	$a0
}
rule Win_Trojan__2103_0004_001_1
{
strings:
	$a0 = { 33c9b8004299cd21b91a00baba01b440cd21b801575a59cd21b43ecd21585a1f59cd215a1fb8 }


condition:
	$a0
}
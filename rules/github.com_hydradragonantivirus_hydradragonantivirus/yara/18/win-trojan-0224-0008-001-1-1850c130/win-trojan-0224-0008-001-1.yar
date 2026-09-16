rule Win_Trojan__0224_0008_001_1
{
strings:
	$a0 = { 33c9b8004233d2cd21baa304b44059cd21b801575a59cd21b43ecd21585a1f59cd215a1fb8 }


condition:
	$a0
}
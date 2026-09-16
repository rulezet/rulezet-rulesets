rule Win_Trojan__0580_0008_000_1
{
strings:
	$a0 = { cd21c3b43ecd21c3b43fcd21c3b440cd21c3b8004233c933d2cd21c3b8024233c933d2cd21 }


condition:
	$a0
}
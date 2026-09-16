rule Win_Trojan_Scroll_2
{
strings:
	$a0 = { b958028d940001cd213bc17531c6840301e9a19eff2d030089840401b8004233c933d2cd21b4 }


condition:
	$a0
}
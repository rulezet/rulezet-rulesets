rule Win_Trojan_Ghost_3
{
strings:
	$a0 = { bc013412b80103b90100cd1333c0b9fe018bfbf3aa8bfb81c7be01bef001b10df3a4b80103 }


condition:
	$a0
}
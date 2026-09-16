rule Win_Trojan_Trivial_166
{
strings:
	$a0 = { ba1d01b44ecd21b8023dba9e00cd218bd8b92100ba0001b440cd21 }


condition:
	$a0
}
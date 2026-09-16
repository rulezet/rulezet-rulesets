rule Win_Trojan_SillyC_29
{
strings:
	$a0 = { ffb43fcd2133d28bca813ebd004b4b741550b80042cd21b44033d259890e6d0083c17c90cd21 }


condition:
	$a0
}
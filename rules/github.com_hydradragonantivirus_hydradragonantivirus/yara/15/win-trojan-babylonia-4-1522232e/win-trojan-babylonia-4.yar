rule Win_Trojan_Babylonia_4
{
strings:
	$a0 = { 575651b80d0a626566ababb8989691dff7d0abb8c9cbcbdff7d0abe8e1feffff66b80d0a66ab }


condition:
	$a0
}
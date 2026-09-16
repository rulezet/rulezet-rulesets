rule Win_Trojan_SillyOC_1
{
strings:
	$a0 = { 33c9cd21721cb8023dba9e00cd2193b440ba0001b91a0190cd21b43ecd21b44febd933c98e }


condition:
	$a0
}
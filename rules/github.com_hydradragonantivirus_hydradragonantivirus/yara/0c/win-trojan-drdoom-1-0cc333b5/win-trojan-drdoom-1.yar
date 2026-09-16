rule Win_Trojan_DrDoom_1
{
strings:
	$a0 = { 77202d0300a39100b440b91b0190cd217210b8004233c9cd21b440b104ba9000cd21b43ecd }


condition:
	$a0
}
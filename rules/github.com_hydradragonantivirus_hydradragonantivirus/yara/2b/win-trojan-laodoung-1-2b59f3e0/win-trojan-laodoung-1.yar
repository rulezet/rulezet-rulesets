rule Win_Trojan_LaoDoung_1
{
strings:
	$a0 = { a34c00061ff6c2807539bb007eba8001 }


condition:
	$a0
}
rule Win_Trojan_Trivial_85
{
strings:
	$a0 = { bad401cd21b44e33c9ba9901cd217303eb7c90b8003dbaf201cd21727193b43fb90200bac801cd218b36c8 }


condition:
	$a0
}
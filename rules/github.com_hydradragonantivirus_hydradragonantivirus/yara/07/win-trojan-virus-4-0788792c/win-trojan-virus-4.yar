rule Win_Trojan_Virus_4
{
strings:
	$a0 = { 5a595b582eff2ee401b440a9b43fbaec01b9e4010e1fe8050072022bc1c3bb }


condition:
	$a0
}
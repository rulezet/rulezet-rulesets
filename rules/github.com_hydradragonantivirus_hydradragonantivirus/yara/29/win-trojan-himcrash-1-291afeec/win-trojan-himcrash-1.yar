rule Win_Trojan_Himcrash_1
{
strings:
	$a0 = { 558bec83ec1053e8560100008bd885db7572 }

	$a1 = { 5c00480069006d00430072006100730068 }


condition:
	$a0 and $a1
}
rule Win_Trojan_Borderline_1
{
strings:
	$a0 = { cd21891e94018c069601ba8601b8 }


condition:
	$a0
}
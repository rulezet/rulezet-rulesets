rule Win_Trojan_Small_4529
{
strings:
	$a0 = { 8da80d??400068533445006a006a00ff153c??400029d529c5e8 }


condition:
	$a0
}
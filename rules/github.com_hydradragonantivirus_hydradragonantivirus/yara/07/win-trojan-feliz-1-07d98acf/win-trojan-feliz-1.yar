rule Win_Trojan_Feliz_1
{
strings:
	$a0 = { b992029c2eff1ea7017303eb3290bf0001b0bdaa81c605018bc6abb855c3ab33c933d2b80042 }


condition:
	$a0
}
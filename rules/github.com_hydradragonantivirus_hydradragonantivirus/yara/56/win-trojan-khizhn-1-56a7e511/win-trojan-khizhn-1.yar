rule Win_Trojan_Khizhn_1
{
strings:
	$a0 = { bac402cd217303e997008bd8b43fb90300ba3b02cd217303e982002ea19a008bf03d00fa7602eb }


condition:
	$a0
}
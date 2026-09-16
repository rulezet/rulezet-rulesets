rule Win_Trojan_Seeg_7
{
strings:
	$a0 = { cd200092bf0fd259c75c2804679391061886c2c2470000ea0c6fe0105f3099de5f10bd116cb58210 }


condition:
	$a0
}
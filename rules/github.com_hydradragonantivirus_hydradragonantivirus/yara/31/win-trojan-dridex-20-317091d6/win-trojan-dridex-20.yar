rule Win_Trojan_Dridex_20
{
strings:
	$a0 = { 31D28B??24??000000F7[0-32]8B8424[16-64]0FB60?[0-32]0FB6 }

	$a1 = { 7064682E646C6C }


condition:
	$a0 and $a1
}
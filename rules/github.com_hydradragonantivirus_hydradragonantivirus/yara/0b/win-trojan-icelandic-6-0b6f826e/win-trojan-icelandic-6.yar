rule Win_Trojan_Icelandic_6
{
strings:
	$a0 = { 030003d8438ec333f633ff0e1fb9d007 }


condition:
	$a0
}
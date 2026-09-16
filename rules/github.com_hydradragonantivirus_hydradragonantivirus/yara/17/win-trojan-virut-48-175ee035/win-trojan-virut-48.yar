rule Win_Trojan_Virut_48
{
strings:
	$a0 = { e8??000000[0-50]8602(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8802[0-50]ffe6 }


condition:
	$a0
}
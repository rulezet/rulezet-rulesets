rule Win_Trojan_Virut_266
{
strings:
	$a0 = { e8??000000[0-60]8607(f9|fc|66|eb|89|87|f8|f5|90)[0-25]8607[0-95]ffe2 }


condition:
	$a0
}
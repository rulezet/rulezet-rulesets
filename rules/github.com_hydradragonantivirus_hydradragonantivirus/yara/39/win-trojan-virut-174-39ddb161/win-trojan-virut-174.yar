rule Win_Trojan_Virut_174
{
strings:
	$a0 = { e8??000000[0-100]8601(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8601c3 }


condition:
	$a0
}
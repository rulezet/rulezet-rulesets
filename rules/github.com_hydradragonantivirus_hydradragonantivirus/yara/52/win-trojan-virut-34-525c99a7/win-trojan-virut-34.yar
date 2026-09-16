rule Win_Trojan_Virut_34
{
strings:
	$a0 = { e8??000000[0-50]8601(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8601[0-50]ffe7 }


condition:
	$a0
}
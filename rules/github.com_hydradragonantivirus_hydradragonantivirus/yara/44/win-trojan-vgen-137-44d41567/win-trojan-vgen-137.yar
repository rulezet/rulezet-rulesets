rule Win_Trojan_Vgen_137
{
strings:
	$a0 = { 80fc02740580fc0375130af6750f83f901750acdfe7203e80800ca02002eff2ef8019c50535152 }


condition:
	$a0
}
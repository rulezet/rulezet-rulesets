rule Win_Trojan_FeelBad_1
{
strings:
	$a0 = { 40008ed8bb6c008a071f24033c037506bb7804e80100c3 }


condition:
	$a0
}
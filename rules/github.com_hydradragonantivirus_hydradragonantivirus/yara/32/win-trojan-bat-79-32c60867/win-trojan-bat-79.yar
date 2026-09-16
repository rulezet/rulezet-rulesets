rule Win_Trojan_BAT_79
{
strings:
	$a0 = { 74696d652030303a30303a30302c3030 }

	$a1 = { 737562737420653a20613a5c203e6e756c22 }


condition:
	$a0 and $a1
}
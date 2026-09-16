rule Win_Trojan_PePatch_1
{
strings:
	$a0 = { 2f63676d2d62696e2f44777071336c6c2e636769 }

	$a1 = { 3064617931303131746d }


condition:
	$a0 and $a1
}
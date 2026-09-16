rule Win_Trojan_Erasmus_2
{
strings:
	$a0 = { 064c002e898423fb2e8c8425fbc41e }


condition:
	$a0
}
rule Win_Trojan_Beep_1
{
strings:
	$a0 = { 502d004b7476585080ec4e740a585080ec4f7403e98b022e }


condition:
	$a0
}
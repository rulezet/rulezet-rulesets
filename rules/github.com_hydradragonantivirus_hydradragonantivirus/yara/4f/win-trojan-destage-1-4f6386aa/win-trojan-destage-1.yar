rule Win_Trojan_Destage_1
{
strings:
	$a0 = { 15998edabb107cb95e01281f43e2fb9ee2ce1390d3291b9b451cc8ddfd24ade0affad5a4b0ff68 }


condition:
	$a0
}
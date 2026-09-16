rule Win_Trojan_Requires_2
{
strings:
	$a0 = { 538bd880ff3d741381fb004b740a5b2eff2e8e }


condition:
	$a0
}
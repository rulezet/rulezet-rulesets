rule Win_Trojan_SVC_20
{
strings:
	$a0 = { 1680fc11740e80fc1274099d2eff2e }


condition:
	$a0
}
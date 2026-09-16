rule Win_Trojan_SillyC_210
{
strings:
	$a0 = { 03531e06b86235cd218cc00bc3750eb82135cd218bd3061fb86225cd21071f5b53bed001817002886b8b4006a3 }


condition:
	$a0
}
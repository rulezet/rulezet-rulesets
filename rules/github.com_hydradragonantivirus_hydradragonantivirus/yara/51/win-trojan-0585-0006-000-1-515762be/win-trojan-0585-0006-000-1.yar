rule Win_Trojan__0585_0006_000_1
{
strings:
	$a0 = { 450a53e85500e85dfd5bb9e803ba2b04b440cc721ab800422bc999ccb91800ba1304b440cce440 }


condition:
	$a0
}
rule Win_Trojan_Pdp_1
{
strings:
	$a0 = { 8bec1e065053515256572e803e12010075352ec6061301 }


condition:
	$a0
}
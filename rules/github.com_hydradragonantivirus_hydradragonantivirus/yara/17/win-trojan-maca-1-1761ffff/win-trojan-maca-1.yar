rule Win_Trojan_Maca_1
{
strings:
	$a0 = { 05e85f00721bb91800bafc04b440cd21720fe85300720ab9e803ba0001b440cd218b1efa04 }


condition:
	$a0
}
rule Win_Trojan_Bancos_1025
{
strings:
	$a0 = { 6f296638345a89b975fe7981161ddb849e9cdd5c38960c7a7488f1071aae9c2033b0b1d4bcbb9ce35953ee1e6505097beddd5c495948d2a00a360aca21f13fda }


condition:
	$a0
}
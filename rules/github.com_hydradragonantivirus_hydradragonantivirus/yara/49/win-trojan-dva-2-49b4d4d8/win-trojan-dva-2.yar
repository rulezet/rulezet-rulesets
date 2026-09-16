rule Win_Trojan_DVA_2
{
strings:
	$a0 = { 8bf281ee0301c35eeb0790eb0490ba00008d94ca02b92000b44ecd217342e9c300b43db0028d94d002cd21898456 }


condition:
	$a0
}
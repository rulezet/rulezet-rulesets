rule Win_Trojan_Chris_1
{
strings:
	$a0 = { 052eff2efc01061e5557565251535090901e5231 }


condition:
	$a0
}
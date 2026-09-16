rule Win_Trojan_Elephant_1
{
strings:
	$a0 = { c0a35e00be40008ec626803e3f0000761a833e5e000075138c1646008e1644008b264800e8 }


condition:
	$a0
}
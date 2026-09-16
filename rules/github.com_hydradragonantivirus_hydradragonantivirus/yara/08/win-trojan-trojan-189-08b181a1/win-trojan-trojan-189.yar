rule Win_Trojan_Trojan_189
{
strings:
	$a0 = { 575153508b5e028a07750e93bfe700b92100f2afff45bc8ac5984001 }


condition:
	$a0
}
rule Win_Trojan_Meihua_1
{
strings:
	$a0 = { c70661053e009c580d0003509d90909090909090 }


condition:
	$a0
}
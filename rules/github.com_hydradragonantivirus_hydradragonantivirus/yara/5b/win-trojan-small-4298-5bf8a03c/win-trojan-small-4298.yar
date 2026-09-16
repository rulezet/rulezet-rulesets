rule Win_Trojan_Small_4298
{
strings:
	$a0 = { 909090909090609c9d61e900000000685fa04000eb01c1c3 }


condition:
	$a0
}
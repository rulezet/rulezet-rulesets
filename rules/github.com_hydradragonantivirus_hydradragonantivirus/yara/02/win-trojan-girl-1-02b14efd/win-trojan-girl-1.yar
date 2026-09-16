rule Win_Trojan_Girl_1
{
strings:
	$a0 = { 803e5808007409fabce10b8cc08ed0fb2e8c06dc072ea3da07b8dcfecd213d241375422e803e5808017410b8efcdbf }


condition:
	$a0
}
rule Win_Trojan_Shame_1
{
strings:
	$a0 = { 9698018e9e9a01cd215b0e1fc38db6bb018134ce164646 }


condition:
	$a0
}
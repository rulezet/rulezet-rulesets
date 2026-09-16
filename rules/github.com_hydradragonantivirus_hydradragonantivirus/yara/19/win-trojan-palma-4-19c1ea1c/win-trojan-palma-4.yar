rule Win_Trojan_Palma_4
{
strings:
	$a0 = { d581c20401b98202cd213ec686710301908f45028f }


condition:
	$a0
}
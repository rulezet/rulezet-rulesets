rule Win_Trojan_VB_275
{
strings:
	$a0 = { c745d44c354000c745cc08000000ff15081140008d55dc6a0252ff15a01040 }


condition:
	$a0
}
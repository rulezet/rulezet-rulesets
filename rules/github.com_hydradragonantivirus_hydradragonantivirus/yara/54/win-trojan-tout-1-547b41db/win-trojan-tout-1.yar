rule Win_Trojan_Tout_1
{
strings:
	$a0 = { 0156fc8b961a02b971008bfeadd2ce33c2abe2f8c3 }


condition:
	$a0
}
rule Win_Trojan_VGEN_94
{
strings:
	$a0 = { 018bf7acd0c8aa81fecc0275f6beea028bfeacd0c8aa81fede0875f671ffff9b427affffea1869bb7f00027dbf0e }


condition:
	$a0
}
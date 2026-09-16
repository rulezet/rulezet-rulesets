rule Win_Trojan_Ascent_1
{
strings:
	$a0 = { 7c1640ef734d80beff1110fe45750e0700ff4d75070701180c077438154483410e154e742a0e }


condition:
	$a0
}
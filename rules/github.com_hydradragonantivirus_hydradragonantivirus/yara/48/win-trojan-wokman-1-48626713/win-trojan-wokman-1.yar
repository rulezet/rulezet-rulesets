rule Win_Trojan_Wokman_1
{
strings:
	$a0 = { 786c69622e67657462796e616d6528617272286929292c2022776f6b6d616e2229 }


condition:
	$a0
}
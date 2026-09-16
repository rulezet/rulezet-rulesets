rule Win_Trojan_Glitter_1
{
strings:
	$a0 = { 050e07c6441d908a5420b99504bb2300301043e2fbc3 }


condition:
	$a0
}
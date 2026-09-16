rule Win_Trojan_Prism_2
{
strings:
	$a0 = { fa97edfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdd599b198fcb8e499e7e6 }


condition:
	$a0
}
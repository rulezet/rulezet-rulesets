rule Win_Trojan_JoJo_1
{
strings:
	$a0 = { b42ccd2180fd13720ab8cd20a3000153e9c702 }


condition:
	$a0
}
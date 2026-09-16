rule Win_Trojan_Fiume_1
{
strings:
	$a0 = { 4b696c6c81cc10000a840800ff030300416e746964656c657465 }


condition:
	$a0
}
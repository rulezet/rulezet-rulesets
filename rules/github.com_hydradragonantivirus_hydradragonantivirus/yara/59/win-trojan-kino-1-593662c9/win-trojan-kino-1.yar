rule Win_Trojan_Kino_1
{
strings:
	$a0 = { 6a006a00c704244e54444cc74424044c000000546a }


condition:
	$a0
}
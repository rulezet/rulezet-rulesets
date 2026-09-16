rule Win_Trojan_Gosia_1
{
strings:
	$a0 = { b90000b443cd2172358bd681c27001b0 }


condition:
	$a0
}
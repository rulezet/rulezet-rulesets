rule Win_Trojan_Loadhigh_1
{
strings:
	$a0 = { 8000bbbb06cd137219beb908c7040602b80302b90100ba8000bbbb06cd13b007cd29b80058cd21 }


condition:
	$a0
}
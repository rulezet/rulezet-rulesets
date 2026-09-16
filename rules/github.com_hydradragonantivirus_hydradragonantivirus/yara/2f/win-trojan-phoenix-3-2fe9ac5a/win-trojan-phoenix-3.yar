rule Win_Trojan_Phoenix_3
{
strings:
	$a0 = { 031f8bf333c0ba54025233472243434a7df85931442246464979f8 }


condition:
	$a0
}
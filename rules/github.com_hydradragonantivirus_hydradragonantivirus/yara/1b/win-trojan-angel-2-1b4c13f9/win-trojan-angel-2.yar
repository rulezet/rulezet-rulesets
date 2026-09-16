rule Win_Trojan_Angel_2
{
strings:
	$a0 = { b440b903008d953102cd21b80242998bcacd21b4408d950301b9b401cd21b801578b54188b4c16 }


condition:
	$a0
}
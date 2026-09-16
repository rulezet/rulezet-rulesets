rule Win_Trojan_GirlFriend_4
{
strings:
	$a0 = { 5c43757272656e7456657273696f6e5c52756e[0-11]57696e646c6c2e657865[0-68]2d207a6162696a }


condition:
	$a0
}
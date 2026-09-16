rule Win_Trojan_Cannibal_3
{
strings:
	$a0 = { e0cd21e84f002e8b1e00e081fb9393742e33c9e83600e84100b440b91301ba0001cd21b80157 }


condition:
	$a0
}
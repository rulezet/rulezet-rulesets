rule Win_Trojan_Cannibal_2
{
strings:
	$a0 = { e847002e8b1e00e081fb9393742e33c9e82e00e83900b440b9ee00ba0001cd21b801572e8b0e9600 }


condition:
	$a0
}
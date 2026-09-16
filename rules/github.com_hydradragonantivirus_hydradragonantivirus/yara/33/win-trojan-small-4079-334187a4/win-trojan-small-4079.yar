rule Win_Trojan_Small_4079
{
strings:
	$a0 = { b845736600682a02000050e816000000 }


condition:
	$a0
}
rule Win_Trojan_IRC_3
{
strings:
	$a0 = { 6d49524324eb40285f66612a33050e0f21ff71318c3e6c1c73203370d5b1f6974dc76d61732b }


condition:
	$a0
}
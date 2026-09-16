rule Win_Trojan_VB_1503
{
strings:
	$a0 = { 6c666f6c646572283129202620225c7733322e6d736e7a796d2e62617422 }


condition:
	$a0
}
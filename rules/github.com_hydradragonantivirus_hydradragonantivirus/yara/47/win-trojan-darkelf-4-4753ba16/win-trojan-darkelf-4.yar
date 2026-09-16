rule Win_Trojan_DarkElf_4
{
strings:
	$a0 = { 0e1fb9ce008b84ab082bc33020d0c4d0c402e0fec0d0c843e2f18984 }


condition:
	$a0
}
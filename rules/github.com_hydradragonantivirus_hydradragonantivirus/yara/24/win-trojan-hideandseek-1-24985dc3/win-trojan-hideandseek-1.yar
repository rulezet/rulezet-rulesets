rule Win_Trojan_HideandSeek_1
{
strings:
	$a0 = { b923008134ffff4646e2f8ba660203d5b94600bb0100 }


condition:
	$a0
}
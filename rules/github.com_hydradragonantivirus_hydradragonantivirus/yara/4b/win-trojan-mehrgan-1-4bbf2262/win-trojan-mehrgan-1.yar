rule Win_Trojan_Mehrgan_1
{
strings:
	$a0 = { 4b7505b853569dcf80fc4b742780fc56742280fc4374 }


condition:
	$a0
}
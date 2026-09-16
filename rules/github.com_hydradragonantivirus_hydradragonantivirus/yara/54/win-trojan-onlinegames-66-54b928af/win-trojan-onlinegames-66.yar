rule Win_Trojan_OnlineGames_66
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d736531327964616d2e657865 }


condition:
	$a0
}
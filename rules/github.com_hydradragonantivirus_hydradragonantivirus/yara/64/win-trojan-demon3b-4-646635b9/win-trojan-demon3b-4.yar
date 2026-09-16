rule Win_Trojan_Demon3b_4
{
strings:
	$a0 = { 1e04008a0fc607cf9c5880e4fe509d880f595b581fc3 }


condition:
	$a0
}
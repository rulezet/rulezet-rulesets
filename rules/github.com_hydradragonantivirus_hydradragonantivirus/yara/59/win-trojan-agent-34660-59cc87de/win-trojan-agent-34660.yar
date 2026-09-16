rule Win_Trojan_Agent_34660
{
strings:
	$a0 = { b918e403004981e930e0030081e98f01000081e958020000516800e0ddff68f5cfdeff }


condition:
	$a0
}
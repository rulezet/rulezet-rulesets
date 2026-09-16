rule Win_Trojan_Agent_35381
{
strings:
	$a0 = { 5c52756e }

	$a1 = { 433a5c62636b2e626174[0-10]633a5c626f7272612e626174 }

	$a2 = { 633a5c6d38302e636f6d }


condition:
	$a0 and $a1 and $a2
}
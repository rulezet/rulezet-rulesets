rule Win_Trojan_Delphine_1
{
strings:
	$a0 = { 505b4c4c58fb3bc37402cd204444b8d0decd213dd0de74751eb9100033c08ec0268b368400 }


condition:
	$a0
}
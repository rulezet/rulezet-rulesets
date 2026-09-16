rule Win_Trojan_Onlinegames_31
{
strings:
	$a0 = { 4542364334343939423035462e455845 }

	$a1 = { 474554 }

	$a2 = { 4d79417070 }

	$a3 = { 534d53434f44453a }

	$a4 = { 574f57 }

	$a5 = { 6661697279636c69656e742e657865 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}
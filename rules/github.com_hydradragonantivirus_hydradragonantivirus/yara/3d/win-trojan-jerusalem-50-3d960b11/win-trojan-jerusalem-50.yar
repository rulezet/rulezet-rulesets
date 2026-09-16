rule Win_Trojan_Jerusalem_50
{
strings:
	$a0 = { 01e89e08e8b501e84e02e82702e85302e86002b4fe8b0e1c0181c10001ba00f08ec233f626833c00740a8cc2 }


condition:
	$a0
}
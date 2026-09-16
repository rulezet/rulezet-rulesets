rule Win_Trojan_Mainman_9
{
strings:
	$a0 = { b9380001ca81ed0601b90300bf50018db6040483ef5057f3a4b71a8d964e048ae7cd21e8c002b42acd213c00 }


condition:
	$a0
}
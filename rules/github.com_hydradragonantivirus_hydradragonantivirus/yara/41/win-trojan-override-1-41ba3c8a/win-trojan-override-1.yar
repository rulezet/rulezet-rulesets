rule Win_Trojan_Override_1
{
strings:
	$a0 = { 21f8c3b43b8d162202cd21c3b9e8008d1e05018b07358b00890743e2f6c3bbff29438bc3cd21c3 }


condition:
	$a0
}
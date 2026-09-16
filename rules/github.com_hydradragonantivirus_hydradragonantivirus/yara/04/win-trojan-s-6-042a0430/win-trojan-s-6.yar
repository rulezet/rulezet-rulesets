rule Win_Trojan_S_6
{
strings:
	$a0 = { 7ef800750bb8ec1750e8550959e8a9ffb81a1850e84a0959b8dc0550e8e41159b8481850e83a09 }


condition:
	$a0
}
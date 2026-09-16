rule Win_Trojan_Mybot_13
{
strings:
	$a0 = { 31539139e6cac742e6e42c93c4b7048bd579e13a8b94efbac6e556f35c162ab58a895f0a485eee02f0ddce40aefb00da2a72bca070280642c2a7c8f487bfe536 }


condition:
	$a0
}
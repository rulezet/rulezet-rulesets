rule Win_Trojan_Agent_32724
{
strings:
	$a0 = { bf2e4c184a8d367d0762db6a62606d6959b6d5be2f31ef40a5b7b07d4017be417af381ba4cdc9847c04a34f353cb20f1ac45d998607d8a5f6a446ec4 }


condition:
	$a0
}
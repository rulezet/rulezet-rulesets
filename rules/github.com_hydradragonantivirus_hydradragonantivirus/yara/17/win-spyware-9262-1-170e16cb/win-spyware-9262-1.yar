rule Win_Spyware_9262_1
{
strings:
	$a0 = { f85dc38bc0832d8476400001c3ffffffff17000000796f756d6569796f7567616f63756fa1a3a1a3a1a3a1a300 }


condition:
	$a0
}
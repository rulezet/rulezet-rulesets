rule Win_Trojan_Peed_15
{
strings:
	$a0 = { e8adf023fe6e5b4a324bfe86211ff1415233a1e6f79d9154b9738b7fae20a0a9 }


condition:
	$a0
}
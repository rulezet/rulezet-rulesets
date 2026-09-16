rule Win_Trojan_Disque_1
{
strings:
	$a0 = { d780fd0075d280fa8075cdb103ebc9b80103b90300cd13061fc35026a1ba913dc002587404 }


condition:
	$a0
}
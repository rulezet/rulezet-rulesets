rule Win_Trojan_GeldWash_2
{
strings:
	$a0 = { a32401a13e01a32601a14001a328018b1e1401b4408d0e0e088d1603012bca030e4601cd21 }


condition:
	$a0
}
rule Win_Trojan_Poje_1
{
strings:
	$a0 = { 061ef85150f8e800005ef883ee0af8bb260003def82e8a945407f8b92d072e3017f843e2f9 }


condition:
	$a0
}
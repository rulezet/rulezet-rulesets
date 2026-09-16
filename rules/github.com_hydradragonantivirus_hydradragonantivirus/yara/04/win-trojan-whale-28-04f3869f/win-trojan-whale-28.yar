rule Win_Trojan_Whale_28
{
strings:
	$a0 = { 0300bb01565b81eb9f23b93489b985 }


condition:
	$a0
}
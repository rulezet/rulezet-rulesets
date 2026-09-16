rule Win_Trojan_Flashback_22
{
strings:
	$a0 = { 5061796c6f61642e6a617661 }

	$a1 = { 2f746d702f2e737973656e746572 }


condition:
	$a0 and $a1
}